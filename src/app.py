"""
FastAPI Web Application with Dashboard
Main entry point for WebSecScanner web interface
"""
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import uvicorn
import logging
import os

from database import init_db, get_db, User, Scan, Vulnerability, Organization
from utils.auth import hash_password, verify_password, create_access_token, decode_access_token
from scanner import SecurityScanner
from report_generator import ReportGenerator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Lifespan context manager for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    logger.info("Database initialized")
    
    # Create default admin user if not exists
    db = next(get_db())
    admin = db.query(User).filter(User.email == "admin@websecscanner.com").first()
    if not admin:
        admin = User(
            email="admin@websecscanner.com",
            username="admin",
            hashed_password=hash_password("admin123"),
            full_name="Administrator",
            is_admin=True
        )
        db.add(admin)
        db.commit()
        logger.info("Default admin user created")
    
    yield
    
    # Shutdown
    logger.info("Application shutting down")


# Initialize FastAPI app with lifespan
app = FastAPI(
    title="WebSecScanner API",
    description="Web Application Security Scanner",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Templates directory (handle both direct run and module import)
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
if not os.path.exists(templates_dir):
    templates_dir = "src/templates"
templates = Jinja2Templates(directory=templates_dir)


# Pydantic models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class ScanCreate(BaseModel):
    target_url: str
    scan_types: Optional[List[str]] = None


class ScanResponse(BaseModel):
    id: int
    scan_id: str
    target_url: str
    scan_status: str
    risk_score: float
    risk_level: str
    vulnerabilities_found: int
    scan_date: datetime
    
    class Config:
        from_attributes = True


# Dependency to get current user
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    token = credentials.credentials
    payload = decode_access_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    
    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == int(user_id)).first()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    return user


# Routes

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Root endpoint - dashboard"""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/api/auth/register", response_model=TokenResponse)
async def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """Register new user"""
    # Check if user exists
    existing_user = db.query(User).filter(
        (User.email == user_data.email) | (User.username == user_data.username)
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email or username already exists"
        )
    
    # Create new user
    new_user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Generate token
    token = create_access_token({"sub": str(new_user.id)})
    
    return TokenResponse(
        access_token=token,
        user={
            "id": new_user.id,
            "email": new_user.email,
            "username": new_user.username,
            "full_name": new_user.full_name
        }
    )


@app.post("/api/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """User login"""
    user = db.query(User).filter(User.email == credentials.email).first()
    
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    
    # Generate token
    token = create_access_token({"sub": str(user.id)})
    
    return TokenResponse(
        access_token=token,
        user={
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
            "is_admin": user.is_admin
        }
    )


@app.get("/api/auth/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "is_admin": current_user.is_admin
    }


@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create and start a new security scan"""
    # Create scan record
    scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    scan = Scan(
        scan_id=scan_id,
        target_url=scan_data.target_url,
        scan_status="pending",
        scan_types=scan_data.scan_types,
        user_id=current_user.id
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Start scan in background
    background_tasks.add_task(run_scan, scan.id, scan_data.target_url, scan_data.scan_types)
    
    return scan


def run_scan(scan_id: int, target_url: str, scan_types: Optional[List[str]]):
    """Background task to run security scan"""
    db = next(get_db())
    
    try:
        # Update status
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        scan.scan_status = "running"
        db.commit()
        
        # Run scanner
        scanner = SecurityScanner()
        results = scanner.scan(target_url, scan_types=scan_types)
        
        # Update scan with results
        scan.scan_status = "completed"
        scan.vulnerabilities_found = results.get('vulnerabilities_found', 0)
        scan.risk_score = results.get('risk_score', 0.0)
        scan.risk_level = results.get('risk_level', 'INFO')
        scan.severity_distribution = results.get('severity_distribution', {})
        scan.scan_duration = results.get('scan_duration', 0)
        scan.parameters_tested = results.get('parameters_tested', 0)
        scan.completed_at = datetime.utcnow()
        
        # Save vulnerabilities
        for vuln_data in results.get('vulnerabilities', []):
            vuln = Vulnerability(
                scan_id=scan.id,
                vuln_type=vuln_data.get('type'),
                subtype=vuln_data.get('subtype'),
                severity=vuln_data.get('severity'),
                cvss_score=vuln_data.get('cvss_score'),
                cvss_vector=vuln_data.get('cvss_vector'),
                location=vuln_data.get('location'),
                parameter=vuln_data.get('parameter'),
                payload=vuln_data.get('payload'),
                evidence=vuln_data.get('evidence'),
                description=vuln_data.get('description'),
                remediation=vuln_data.get('remediation'),
                confidence=vuln_data.get('confidence')
            )
            db.add(vuln)
        
        db.commit()
        logger.info(f"Scan {scan_id} completed successfully")
    
    except Exception as e:
        logger.error(f"Error running scan {scan_id}: {e}")
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.scan_status = "failed"
            db.commit()


@app.get("/api/scans", response_model=List[ScanResponse])
async def get_scans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = 50,
    offset: int = 0
):
    """Get user's scans"""
    scans = db.query(Scan).filter(Scan.user_id == current_user.id)\
        .order_by(Scan.scan_date.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    
    return scans


@app.get("/api/scans/{scan_id}")
async def get_scan_details(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed scan results"""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    
    return {
        "id": scan.id,
        "scan_id": scan.scan_id,
        "target_url": scan.target_url,
        "scan_status": scan.scan_status,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "vulnerabilities_found": scan.vulnerabilities_found,
        "severity_distribution": scan.severity_distribution,
        "scan_duration": scan.scan_duration,
        "scan_date": scan.scan_date.isoformat(),
        "vulnerabilities": [
            {
                "id": v.id,
                "vulnerability_type": v.vuln_type,
                "title": f"{v.vuln_type} - {v.subtype or 'Detected'}",
                "subtype": v.subtype,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "location": v.location,
                "parameter": v.parameter,
                "description": v.description,
                "evidence": v.evidence,
                "remediation": v.remediation,
                "confidence": v.confidence
            }
            for v in vulnerabilities
        ]
    }


@app.get("/api/scans/{scan_id}/report")
async def download_scan_report(
    scan_id: int,
    format: str = "json",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download scan report in specified format"""
    import json
    
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    
    # Prepare scan results
    scan_results = {
        "target_url": scan.target_url,
        "scan_id": scan.scan_id,
        "scan_date": scan.scan_date.isoformat(),
        "scan_status": scan.scan_status,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "vulnerabilities_found": scan.vulnerabilities_found,
        "vulnerabilities": [
            {
                "type": v.vuln_type,
                "subtype": v.subtype,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "location": v.location,
                "parameter": v.parameter,
                "description": v.description,
                "evidence": v.evidence,
                "remediation": v.remediation,
                "confidence": v.confidence,
                "cvss_vector": v.cvss_vector
            }
            for v in vulnerabilities
        ]
    }
    
    # Generate report using ReportGenerator
    report_gen = ReportGenerator(scan_results)
    
    if format == "json":
        content = json.dumps(scan_results, indent=2)
        media_type = "application/json"
        filename = f"scan_{scan.scan_id}.json"
    elif format == "html":
        content = report_gen.generate_html()
        media_type = "text/html"
        filename = f"scan_{scan.scan_id}.html"
    elif format == "csv":
        content = report_gen.generate_csv()
        media_type = "text/csv"
        filename = f"scan_{scan.scan_id}.csv"
    elif format == "markdown":
        content = report_gen.generate_markdown()
        media_type = "text/markdown"
        filename = f"scan_{scan.scan_id}.md"
    else:
        raise HTTPException(status_code=400, detail="Invalid format. Use json, html, csv, or markdown")
    
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/api/dashboard/stats")
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics"""
    total_scans = db.query(Scan).filter(Scan.user_id == current_user.id).count()
    
    recent_scans = db.query(Scan).filter(Scan.user_id == current_user.id)\
        .order_by(Scan.scan_date.desc())\
        .limit(5)\
        .all()
    
    total_vulns = db.query(Vulnerability)\
        .join(Scan)\
        .filter(Scan.user_id == current_user.id)\
        .count()
    
    critical_vulns = db.query(Vulnerability)\
        .join(Scan)\
        .filter(Scan.user_id == current_user.id, Vulnerability.severity == "CRITICAL")\
        .count()
    
    return {
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns,
        "critical_vulnerabilities": critical_vulns,
        "recent_scans": [
            {
                "id": s.id,
                "target_url": s.target_url,
                "risk_level": s.risk_level,
                "scan_date": s.scan_date.isoformat()
            }
            for s in recent_scans
        ]
    }


if __name__ == "__main__":
    # Run with uvicorn
    # Use 127.0.0.1 for Windows compatibility, 0.0.0.0 for Docker
    default_host = "127.0.0.1" if os.name == "nt" else "0.0.0.0"
    
    uvicorn.run(
        "app:app",
        host=os.getenv("HOST", default_host),
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("DEBUG", "False").lower() == "true"
    )
    
    print("\n" + "="*60)
    print(f"🚀 WebSecScanner rodando em http://127.0.0.1:8000")
    print(f"📚 Documentação da API: http://127.0.0.1:8000/docs")
    print(f"👤 Login padrão: admin@websecscanner.com / admin123")
    print("="*60 + "\n")
