"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.database.repository

Data Access Object (DAO) / Repository pattern for executing optimized,
indexed queries against PostgreSQL for flows, alerts, model statuses, and dashboard metrics.
"""

import time
import logging
import copy
import threading
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from src.database.models import (
    FlowModel,
    AlertModel,
    ModelStatusModel,
    UserModel,
    UserSessionModel,
    SensorEnrollmentModel,
    SensorIngestRecordModel,
)

logger = logging.getLogger(__name__)


class FlowRepository:
    """Repository for querying and persisting network flow metadata."""

    @staticmethod
    def get_flows(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        protocol: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        traffic_context: Optional[str] = None,
        sensor_id: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> Tuple[List[FlowModel], int]:
        """Fetch paginated flow records with optional filtering."""
        query = db.query(FlowModel)

        if protocol:
            query = query.filter(FlowModel.protocol.ilike(protocol))
        if src_ip:
            query = query.filter(FlowModel.src_ip == src_ip)
        if dst_ip:
            query = query.filter(FlowModel.dst_ip == dst_ip)
        if traffic_context:
            query = query.filter(FlowModel.traffic_context == traffic_context)
        if sensor_id:
            query = query.filter(FlowModel.sensor_id == sensor_id)
        if user_id:
            query = query.filter(FlowModel.user_id == user_id)

        total = query.count()
        flows = query.order_by(FlowModel.timestamp.desc()).offset(offset).limit(limit).all()
        return flows, total

    @staticmethod
    def get_by_flow_id(db: Session, flow_id: str) -> Optional[FlowModel]:
        """Fetch a single flow by its unique flow_id."""
        return db.query(FlowModel).filter(FlowModel.flow_id == flow_id).first()

    @staticmethod
    def create_or_update(db: Session, flow_data: Dict[str, Any], commit: bool = True) -> FlowModel:
        """Insert or update a flow record based on unique flow_id."""
        fid = flow_data.get("flow_id")
        existing = db.query(FlowModel).filter(FlowModel.flow_id == fid).first()
        valid_cols = {c.name for c in FlowModel.__table__.columns}
        filtered_data = {k: v for k, v in flow_data.items() if k in valid_cols and k != "id"}

        if existing:
            for k, v in filtered_data.items():
                setattr(existing, k, v)
            if commit:
                db.commit()
                db.refresh(existing)
            return existing

        flow = FlowModel(**filtered_data)
        db.add(flow)
        if commit:
            db.commit()
            db.refresh(flow)
        return flow


class AlertRepository:
    """Repository for querying and persisting threat alerts."""

    @staticmethod
    def get_alerts(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        threat_class: Optional[str] = None,
        detector: Optional[str] = None,
        traffic_context: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        sensor_id: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> Tuple[List[AlertModel], int]:
        """Fetch paginated alerts ordered newest first."""
        query = db.query(AlertModel)

        if severity:
            query = query.filter(AlertModel.severity.ilike(severity))
        if threat_class:
            query = query.filter(AlertModel.threat_class.ilike(threat_class))
        if detector:
            query = query.filter(AlertModel.detector.ilike(f"%{detector}%"))
        if traffic_context:
            query = query.filter(AlertModel.traffic_context == traffic_context)
        if start_time is not None:
            query = query.filter(AlertModel.timestamp >= start_time)
        if end_time is not None:
            query = query.filter(AlertModel.timestamp <= end_time)
        if sensor_id:
            query = query.filter(AlertModel.sensor_id == sensor_id)
        if user_id:
            query = query.filter(AlertModel.user_id == user_id)

        total = query.count()
        alerts = query.order_by(AlertModel.timestamp.desc()).offset(offset).limit(limit).all()
        return alerts, total

    @staticmethod
    def get_by_alert_id(db: Session, alert_id: str) -> Optional[AlertModel]:
        """Fetch a single alert by its unique alert_id."""
        return db.query(AlertModel).filter(AlertModel.alert_id == alert_id).first()

    @staticmethod
    def get_recent_alerts(db: Session, limit: int = 20, user_id: Optional[str] = None) -> List[AlertModel]:
        """Fetch the most recent alerts for live dashboard polling."""
        query = db.query(AlertModel)
        if user_id:
            query = query.filter(AlertModel.user_id == user_id)
        return query.order_by(AlertModel.timestamp.desc()).limit(limit).all()

    @staticmethod
    def create_or_update(db: Session, alert_data: Dict[str, Any], commit: bool = True) -> AlertModel:
        """Insert or update an alert record based on unique alert_id."""
        aid = alert_data.get("alert_id")
        existing = db.query(AlertModel).filter(AlertModel.alert_id == aid).first()
        valid_cols = {c.name for c in AlertModel.__table__.columns}
        filtered_data = {k: v for k, v in alert_data.items() if k in valid_cols and k != "id"}

        if existing:
            for k, v in filtered_data.items():
                setattr(existing, k, v)
            if commit:
                db.commit()
                db.refresh(existing)
            return existing

        alert = AlertModel(**filtered_data)
        db.add(alert)
        if commit:
            db.commit()
            db.refresh(alert)
        return alert


class ModelStatusRepository:
    """Repository for querying and updating model compatibility statuses."""

    @staticmethod
    def get_all(db: Session) -> List[ModelStatusModel]:
        """Retrieve all model status records."""
        return db.query(ModelStatusModel).order_by(ModelStatusModel.model_name).all()

    @staticmethod
    def create_or_update(
        db: Session,
        model_name: str,
        status: str,
        compatible: str,
        reason: str
    ) -> ModelStatusModel:
        """Upsert model status record."""
        existing = db.query(ModelStatusModel).filter(ModelStatusModel.model_name == model_name).first()
        if existing:
            existing.status = status
            existing.compatible = compatible
            existing.reason = reason
            db.commit()
            db.refresh(existing)
            return existing

        rec = ModelStatusModel(
            model_name=model_name,
            status=status,
            compatible=compatible,
            reason=reason
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return rec


# Module-level TTL cache for get_overview to prevent database connection exhaustion during high-frequency polling
# Key: user_id (str for authenticated tenant, None for global admin view)
# Value: (timestamp, overview_dict)
_CACHE_LOCK = threading.Lock()
_OVERVIEW_CACHE: Dict[Optional[str], Tuple[float, Dict[str, Any]]] = {}
_OVERVIEW_CACHE_TTL: float = 5.0  # seconds


class DashboardRepository:
    """Repository for aggregated metrics and dashboard overviews."""

    @staticmethod
    def invalidate_overview_cache(user_id: Optional[str] = None) -> None:
        """
        Invalidates overview cache for a specific user or globally.
        When a tenant user_id is provided, evicts that user's cached snapshot
        and the global admin snapshot (None), leaving all other users' caches intact.
        When user_id is None, clears all cached views.
        """
        with _CACHE_LOCK:
            if user_id is not None:
                _OVERVIEW_CACHE.pop(user_id, None)
                _OVERVIEW_CACHE.pop(None, None)
            else:
                _OVERVIEW_CACHE.clear()

    @staticmethod
    def get_alert_summary(db: Session, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Aggregates alert totals, severity counts, and threat class metrics scoped to a user."""
        alert_query = db.query(AlertModel)
        flow_query = db.query(FlowModel)
        if user_id:
            alert_query = alert_query.filter(AlertModel.user_id == user_id)
            flow_query = flow_query.filter(FlowModel.user_id == user_id)

        total_alerts = alert_query.count()
        total_flows = flow_query.count()

        # Severity breakdown
        sev_counts = dict(
            alert_query.with_entities(AlertModel.severity, func.count(AlertModel.id))
            .group_by(AlertModel.severity)
            .all()
        )

        # Threat class breakdown
        tc_counts = dict(
            alert_query.with_entities(AlertModel.threat_class, func.count(AlertModel.id))
            .group_by(AlertModel.threat_class)
            .all()
        )

        unlabeled_count = alert_query.filter(AlertModel.traffic_context == "UNLABELED_LIVE").count()

        return {
            "total_alerts": total_alerts,
            "total_flows": total_flows,
            "benign_count": sev_counts.get("BENIGN", 0),
            "low_count": sev_counts.get("LOW", 0),
            "medium_count": sev_counts.get("MEDIUM", 0),
            "high_count": sev_counts.get("HIGH", 0),
            "critical_count": sev_counts.get("CRITICAL", 0),
            "ddos_count": tc_counts.get("DDoS", 0),
            "botnet_c2_count": tc_counts.get("BOTNET_C2", 0),
            "recon_portscan_count": tc_counts.get("RECON_PORTSCAN", 0),
            "multi_threat_count": tc_counts.get("MULTI_THREAT", 0),
            "unlabeled_live_alerts": unlabeled_count,
        }

    @staticmethod
    def get_overview(db: Session, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Generates comprehensive dashboard overview telemetry scoped strictly to the requesting user."""
        now = time.time()
        with _CACHE_LOCK:
            cached = _OVERVIEW_CACHE.get(user_id)
            if cached is not None and (now - cached[0]) < _OVERVIEW_CACHE_TTL:
                # Return deep copy so callers cannot mutate the cached telemetry in place
                return copy.deepcopy(cached[1])

        flow_query = db.query(FlowModel)
        alert_query = db.query(AlertModel)

        if user_id:
            flow_query = flow_query.filter(FlowModel.user_id == user_id)
            alert_query = alert_query.filter(AlertModel.user_id == user_id)

        total_flows = flow_query.count()
        total_alerts = alert_query.count()

        # In live capture replay, calculate relative to latest alert timestamp if present
        latest_alert = alert_query.order_by(AlertModel.timestamp.desc()).first()
        now_ts = latest_alert.timestamp if latest_alert else now

        alerts_5m = alert_query.filter(AlertModel.timestamp >= (now_ts - 300)).count()
        alerts_15m = alert_query.filter(AlertModel.timestamp >= (now_ts - 900)).count()
        alerts_24h = alert_query.filter(AlertModel.timestamp >= (now_ts - 86400)).count()

        # Severity breakdown
        sev_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "BENIGN": 0
        }
        for sev, count in alert_query.with_entities(AlertModel.severity, func.count(AlertModel.id)).group_by(AlertModel.severity).all():
            sev_counts[sev] = count

        # Threat breakdown
        threat_counts = {
            "DDoS": 0, "BOTNET_C2": 0, "RECON_PORTSCAN": 0, "MULTI_THREAT": 0, "BENIGN": 0
        }
        for tc, count in alert_query.with_entities(AlertModel.threat_class, func.count(AlertModel.id)).group_by(AlertModel.threat_class).all():
            threat_counts[tc] = count

        # Top 5 Source IPs
        top_src = [
            {"ip": ip, "count": cnt}
            for ip, cnt in flow_query.with_entities(FlowModel.src_ip, func.count(FlowModel.id))
            .group_by(FlowModel.src_ip)
            .order_by(desc(func.count(FlowModel.id)))
            .limit(5)
            .all()
        ]

        # Top 5 Destination IPs
        top_dst = [
            {"ip": ip, "count": cnt}
            for ip, cnt in flow_query.with_entities(FlowModel.dst_ip, func.count(FlowModel.id))
            .group_by(FlowModel.dst_ip)
            .order_by(desc(func.count(FlowModel.id)))
            .limit(5)
            .all()
        ]

        # Protocol Breakdown
        proto_counts = dict(
            flow_query.with_entities(FlowModel.protocol, func.count(FlowModel.id))
            .group_by(FlowModel.protocol)
            .all()
        )

        # Model Statuses
        statuses = [m.to_dict() for m in ModelStatusRepository.get_all(db)]

        result = {
            "total_flows": total_flows,
            "total_alerts": total_alerts,
            "alerts_last_5_minutes": alerts_5m,
            "alerts_last_15_minutes": alerts_15m,
            "alerts_last_24_hours": alerts_24h,
            "severity_counts": sev_counts,
            "threat_counts": threat_counts,
            "top_source_ips": top_src,
            "top_destination_ips": top_dst,
            "protocol_counts": proto_counts,
            "model_status": statuses,
        }

        with _CACHE_LOCK:
            # Prune expired keys if cache grows large
            if len(_OVERVIEW_CACHE) > 500:
                expired = [k for k, v in _OVERVIEW_CACHE.items() if (now - v[0]) >= _OVERVIEW_CACHE_TTL]
                for k in expired:
                    _OVERVIEW_CACHE.pop(k, None)
            _OVERVIEW_CACHE[user_id] = (now, copy.deepcopy(result))

        return copy.deepcopy(result)


class UserRepository:
    """Repository for querying, creating, and updating user accounts."""

    @staticmethod
    def get_by_id(db: Session, user_id: str) -> Optional[UserModel]:
        """Fetch user by unique user_id."""
        return db.query(UserModel).filter(UserModel.user_id == user_id).first()

    @staticmethod
    def get_by_email(db: Session, email: str) -> Optional[UserModel]:
        """Fetch user by normalized lowercase email address."""
        normalized = email.strip().lower()
        return db.query(UserModel).filter(func.lower(UserModel.email) == normalized).first()

    @staticmethod
    def create_user(
        db: Session,
        email: str,
        hashed_password: str,
        full_name: str,
        role: str = "analyst",
        is_active: bool = True
    ) -> UserModel:
        """Create a new user account."""
        import uuid
        normalized_email = email.strip().lower()
        user_id = f"user_{uuid.uuid4().hex[:16]}"
        user = UserModel(
            user_id=user_id,
            email=normalized_email,
            hashed_password=hashed_password,
            full_name=full_name.strip(),
            role=role,
            is_active=is_active,
            failed_login_attempts=0
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def record_login_failure(db: Session, user: UserModel, max_attempts: int = 5, lockout_minutes: int = 15) -> UserModel:
        """Increment failed login attempts and apply temporary lockout if threshold is exceeded."""
        from datetime import datetime, timezone, timedelta
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= max_attempts:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def record_login_success(db: Session, user: UserModel) -> UserModel:
        """Reset failed attempts, clear lockout, and update last login timestamp."""
        from datetime import datetime, timezone
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def count_users(db: Session) -> int:
        """Count total registered users."""
        return db.query(UserModel).count()

    @staticmethod
    def count_admins(db: Session) -> int:
        """Count total active administrator accounts."""
        return db.query(UserModel).filter(UserModel.role == "admin", UserModel.is_active == True).count()


class UserSessionRepository:
    """Repository for managing session tokens and server-side invalidation."""

    @staticmethod
    def create_session(
        db: Session,
        user_id: str,
        token_jti: str,
        expires_at,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> UserSessionModel:
        """Record a newly minted session."""
        import uuid
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        session = UserSessionModel(
            session_id=session_id,
            user_id=user_id,
            token_jti=token_jti,
            expires_at=expires_at,
            is_revoked=False,
            ip_address=ip_address,
            user_agent=user_agent[:255] if user_agent else None
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        return session

    @staticmethod
    def is_jti_revoked(db: Session, token_jti: str) -> bool:
        """Check if a session token's JTI has been explicitly revoked or is absent."""
        session = db.query(UserSessionModel).filter(UserSessionModel.token_jti == token_jti).first()
        if session is None:
            return True
        return session.is_revoked

    @staticmethod
    def revoke_session_by_jti(db: Session, token_jti: str) -> bool:
        """Revoke a session by its token JTI."""
        session = db.query(UserSessionModel).filter(UserSessionModel.token_jti == token_jti).first()
        if session:
            session.is_revoked = True
            db.commit()
            return True
        return False

    @staticmethod
    def revoke_all_user_sessions(db: Session, user_id: str) -> int:
        """Revoke all active sessions for a user."""
        count = db.query(UserSessionModel).filter(
            UserSessionModel.user_id == user_id,
            UserSessionModel.is_revoked == False
        ).update({"is_revoked": True})
        db.commit()
        return count


class SensorEnrollmentRepository:
    """Repository for managing enrolled Windows sensors, API key hashes, and telemetry."""

    @staticmethod
    def get_by_sensor_id(db: Session, sensor_id: str) -> Optional[SensorEnrollmentModel]:
        """Lookup sensor by unique sensor_id."""
        return db.query(SensorEnrollmentModel).filter(SensorEnrollmentModel.sensor_id == sensor_id).first()

    @staticmethod
    def get_by_api_key_hash(db: Session, key_hash: str) -> Optional[SensorEnrollmentModel]:
        """Lookup sensor by SHA-256 API key hash."""
        return db.query(SensorEnrollmentModel).filter(SensorEnrollmentModel.api_key_hash == key_hash).first()

    @staticmethod
    def get_all(db: Session, status: Optional[str] = None) -> List[SensorEnrollmentModel]:
        """List all enrolled sensors, optionally filtered by status ('ACTIVE', 'REVOKED')."""
        query = db.query(SensorEnrollmentModel)
        if status:
            query = query.filter(SensorEnrollmentModel.status == status)
        return query.order_by(SensorEnrollmentModel.created_at.desc()).all()

    @staticmethod
    def get_by_user(
        db: Session,
        user_id: Optional[str] = None,
        owner_email: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[SensorEnrollmentModel]:
        """List enrolled sensors owned by a specific user account."""
        query = db.query(SensorEnrollmentModel)
        if user_id and owner_email:
            query = query.filter(
                (SensorEnrollmentModel.user_id == user_id) |
                (SensorEnrollmentModel.owner_email == owner_email)
            )
        elif user_id:
            query = query.filter(SensorEnrollmentModel.user_id == user_id)
        elif owner_email:
            query = query.filter(SensorEnrollmentModel.owner_email == owner_email)

        if status:
            query = query.filter(SensorEnrollmentModel.status == status)
        return query.order_by(SensorEnrollmentModel.created_at.desc()).all()

    @staticmethod
    def enroll_sensor(
        db: Session,
        sensor_id: str,
        name: str,
        api_key_hash: str,
        api_key_prefix: str,
        owner_email: str,
        user_id: Optional[str] = None
    ) -> SensorEnrollmentModel:
        """Enroll a new sensor device with its credential hash and owner association."""
        existing = db.query(SensorEnrollmentModel).filter(SensorEnrollmentModel.sensor_id == sensor_id).first()
        if existing:
            existing.name = name
            existing.api_key_hash = api_key_hash
            existing.api_key_prefix = api_key_prefix
            existing.owner_email = owner_email
            if user_id:
                existing.user_id = user_id
            existing.status = "ACTIVE"
            existing.revoked_at = None
            db.commit()
            db.refresh(existing)
            return existing

        sensor = SensorEnrollmentModel(
            sensor_id=sensor_id,
            name=name,
            api_key_hash=api_key_hash,
            api_key_prefix=api_key_prefix,
            owner_email=owner_email,
            user_id=user_id,
            status="ACTIVE"
        )
        db.add(sensor)
        db.commit()
        db.refresh(sensor)
        return sensor

    @staticmethod
    def revoke_sensor(db: Session, sensor_id: str) -> bool:
        """Revoke a sensor's credential to halt further ingestion."""
        sensor = db.query(SensorEnrollmentModel).filter(SensorEnrollmentModel.sensor_id == sensor_id).first()
        if sensor:
            from datetime import datetime, timezone
            sensor.status = "REVOKED"
            sensor.revoked_at = datetime.now(timezone.utc)
            db.commit()
            return True
        return False

    @staticmethod
    def set_target_state(
        db: Session,
        sensor_id: str,
        target_state: str,
        target_interface: Optional[str] = None
    ) -> Optional[SensorEnrollmentModel]:
        """Set target desired operational state ('RUNNING' or 'STOPPED') for remote sensor."""
        sensor = db.query(SensorEnrollmentModel).filter(SensorEnrollmentModel.sensor_id == sensor_id).first()
        if not sensor:
            return None
        sensor.target_state = target_state
        if target_interface is not None:
            sensor.target_interface = target_interface
        db.commit()
        db.refresh(sensor)
        return sensor

    @staticmethod
    def update_telemetry(
        db: Session,
        sensor_id: str,
        last_ip: Optional[str] = None,
        sensor_version: Optional[str] = None,
        hostname: Optional[str] = None,
        new_packets: int = 0,
        new_flows: int = 0,
        new_alerts: int = 0,
        actual_state: Optional[str] = None
    ) -> Optional[SensorEnrollmentModel]:
        """Update operational telemetry, actual state, and last-seen heartbeat for an active sensor."""
        sensor = db.query(SensorEnrollmentModel).filter(SensorEnrollmentModel.sensor_id == sensor_id).first()
        if not sensor:
            return None

        from datetime import datetime, timezone
        sensor.last_seen_at = datetime.now(timezone.utc)
        if last_ip:
            sensor.last_ip = last_ip
        if sensor_version:
            sensor.sensor_version = sensor_version
        if hostname:
            sensor.hostname = hostname
        if actual_state:
            sensor.actual_state = actual_state

        sensor.packets_uploaded += max(0, new_packets)
        sensor.flows_uploaded += max(0, new_flows)
        sensor.alerts_uploaded += max(0, new_alerts)

        db.commit()
        db.refresh(sensor)
        return sensor


class SensorIngestRepository:
    """Repository for managing idempotency and deduplication of ingested records."""

    @staticmethod
    def is_duplicate(db: Session, sensor_id: str, record_id: str) -> bool:
        """Check if a record has already been ingested from this sensor."""
        return db.query(SensorIngestRecordModel).filter(
            SensorIngestRecordModel.sensor_id == sensor_id,
            SensorIngestRecordModel.record_id == record_id
        ).first() is not None

    @staticmethod
    def record_ingestion(db: Session, sensor_id: str, record_id: str, record_type: str, commit: bool = True) -> bool:
        """Mark a record as ingested for future idempotency checks."""
        try:
            record = SensorIngestRecordModel(
                sensor_id=sensor_id,
                record_id=record_id,
                record_type=record_type
            )
            db.add(record)
            if commit:
                db.commit()
            return True
        except Exception as e:
            if commit:
                db.rollback()
            logger.warning(f"Failed to record ingest idempotency: {e}")
            return False

    @staticmethod
    def get_recent_ingest_records(
        db: Session,
        sensor_id: Optional[str] = None,
        limit: int = 50
    ) -> List[SensorIngestRecordModel]:
        """Retrieve recent ingestion audit records."""
        query = db.query(SensorIngestRecordModel)
        if sensor_id:
            query = query.filter(SensorIngestRecordModel.sensor_id == sensor_id)
        return query.order_by(SensorIngestRecordModel.ingested_at.desc()).limit(limit).all()
