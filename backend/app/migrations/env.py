import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
# Community's own repo root — lets a sibling checkout of the Enterprise
# package (../enterprise/, not pip-installed) still be importable here, e.g.
# `alembic upgrade heads` run straight out of a monorepo-style working copy.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../enterprise")))

from sqlalchemy import engine_from_config, pool
from alembic import context

from app.core.config import settings
from app.models import models  # noqa: F401 — registers core tables with Base.metadata
from app.models import dam     # noqa: F401 — registers Community DAM tables with Base.metadata
from app.core.database import Base

try:
    from metasight_enterprise.models import pam                 # noqa: F401 — registers Enterprise PAM tables, if installed
    from metasight_enterprise.models import sdk_credential       # noqa: F401 — registers Enterprise sdk_credentials table, if installed
    from metasight_enterprise.models import gateway_credential   # noqa: F401 — registers Enterprise gateway_credentials table, if installed
except ImportError:
    pass

alembic_config = context.config

# Override the DB URL from our settings so alembic.ini never needs a hardcoded URL
alembic_config.set_main_option("sqlalchemy.url", settings.SQLALCHEMY_DATABASE_URI.replace("%", "%%"))

target_metadata = Base.metadata


def run_migrations_offline():
    context.configure(
        url=settings.SQLALCHEMY_DATABASE_URI,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = engine_from_config(
        alembic_config.get_section(alembic_config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
