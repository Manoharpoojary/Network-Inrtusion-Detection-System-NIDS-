"""SQLAlchemy models. No IP addresses, MAC addresses or packet payloads are stored."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """Stores timezone-aware datetimes as naive UTC and returns them as aware UTC."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are not allowed; use UTC-aware datetimes")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        return None if value is None else value.replace(tzinfo=UTC)


class Base(DeclarativeBase):
    pass


class Analysis(Base):
    """One unit of submitted work: a single prediction, a batch, or an uploaded CSV."""

    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source: Mapped[str] = mapped_column(String(16), index=True)  # api_single | api_batch | csv
    filename: Mapped[str | None] = mapped_column(String(128))  # sanitised base name only
    status: Mapped[str] = mapped_column(String(16), default="running")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    total_records: Mapped[int] = mapped_column(Integer, default=0)
    benign_count: Mapped[int] = mapped_column(Integer, default=0)
    attack_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    model_version: Mapped[str] = mapped_column(String(32))
    threshold: Mapped[float] = mapped_column(Float)
    ignored_columns_json: Mapped[str | None] = mapped_column(Text)

    predictions: Mapped[list[Prediction]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", passive_deletes=True
    )


class Prediction(Base):
    __tablename__ = "predictions"
    __table_args__ = (Index("ix_predictions_analysis_row", "analysis_id", "row_index"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))
    row_index: Mapped[int] = mapped_column(Integer)  # 0-based position within the analysis
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    label: Mapped[str] = mapped_column(String(8), index=True)
    attack_probability: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    model_version: Mapped[str] = mapped_column(String(32))
    # Selected flow metadata for tables and filtering (no addresses exist in the model schema).
    proto: Mapped[str | None] = mapped_column(String(8))
    flgs: Mapped[str | None] = mapped_column(String(4))
    sport: Mapped[int | None] = mapped_column(Integer)
    dport: Mapped[int | None] = mapped_column(Integer)
    pkts: Mapped[float | None] = mapped_column(Float)
    bytes: Mapped[float | None] = mapped_column(Float)
    dur: Mapped[float | None] = mapped_column(Float)

    analysis: Mapped[Analysis] = relationship(back_populates="predictions")
    alert: Mapped[Alert | None] = relationship(back_populates="prediction", uselist=False)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    prediction_id: Mapped[int] = mapped_column(
        ForeignKey("predictions.id", ondelete="CASCADE"), unique=True
    )
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    label: Mapped[str] = mapped_column(String(8))
    attack_probability: Mapped[float] = mapped_column(Float)
    model_version: Mapped[str] = mapped_column(String(32))
    proto: Mapped[str | None] = mapped_column(String(8), index=True)
    dport: Mapped[int | None] = mapped_column(Integer)
    # The 35 validated model inputs, kept so the alert can be reviewed and explained later.
    features_json: Mapped[str] = mapped_column(Text)
    explanation_json: Mapped[str | None] = mapped_column(Text)

    prediction: Mapped[Prediction] = relationship(back_populates="alert")
    analysis: Mapped[Analysis] = relationship()
