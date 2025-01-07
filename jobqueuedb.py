import json
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session
from sqlalchemy.orm import joinedload
from sqlalchemy import delete, and_
import psycopg2
import shortuuid
from datetime import datetime, timedelta

from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.orm import relationship

from dateutil.relativedelta import relativedelta

from sqlalchemy import func, case
from datetime import datetime, timedelta
from typing import Optional, Tuple


def generate_quarters(start_year: int, start_month: int, end_date: datetime):
    """
    Generate a list of (start_date, end_date) tuples for each quarter.

    Args:
        start_year (int): Starting year.
        start_month (int): Starting month (should be one of 1, 4, 7, 10).
        end_date (datetime): The end date up to which quarters are generated.

    Yields:
        Tuple[str, str]: start_date and end_date in "m/YYYY" format.
    """
    current = datetime(start_year, start_month, 1)
    while current <= end_date:
        # Determine the start and end months of the current quarter
        quarter = (current.month - 1) // 3 + 1
        start_month = 3 * quarter - 2
        end_month = 3 * quarter

        # Define start_date and end_date for the filter
        start_date_str = f"{start_month}/{current.year}"
        
        # Calculate the first day of the next quarter
        next_quarter = current + relativedelta(months=3)
        end_month_next = 3 * (((next_quarter.month - 1) // 3) + 1)
        end_year_next = next_quarter.year
        end_date_str = f"{end_month_next}/{end_year_next}"
        
        yield (start_date_str, end_date_str)
        
        # Move to the next quarter
        current += relativedelta(months=3)

def collect_quarterly_job_counts(config, start_year: int = 2023, start_month: int = 1):
    """
    Collect job counts for each quarter from start_date to today.

    Args:
        start_year (int): The starting year.
        start_month (int): The starting month (1 for Jan, 4 for Apr, etc.).

    Returns:
        pd.DataFrame: DataFrame containing job counts per quarter.
    """
    # Get the current date
    today = datetime.now()
    
    # Ensure the start_month is one of the first months of a quarter
    if start_month not in [1, 4, 7, 10]:
        raise ValueError("start_month must be one of [1, 4, 7, 10]")
    
    # Initialize a list to store data
    data = []
    
    # Generate quarters
    for start_date, end_date in generate_quarters(start_year, start_month, today):
        # Retrieve job counts
        try:
            _, completed, failed, waiting, submitted = check_jobs_all(
                config,
                verbose=False,
                start_date=start_date,
                end_date=end_date
            )
        except Exception as e:
            print(f"Error retrieving data for {start_date} to {end_date}: {e}")
            completed, failed, waiting, submitted = 0, 0, 0, 0  # Assign default values or handle as needed
        
        # Create a quarter label, e.g., "Q1 2020"
        quarter_num = int(start_date.split('/')[0])
        quarter_label = f"{quarter_num}/{start_date.split('/')[1]}"
        
        # Append the data
        
        data.append({
            "year": quarter_label,
            "success": completed,
            "failed": failed,
            "pending": waiting,
            "submitted": submitted
        })
    
    return data

def get_job_info(config, time_delta=3000):
    DB_NAME = config["DB_NAME"]
    DB_HOST = config["DB_HOST"]
    DB_PORT = config["DB_PORT"]
    DB_USER = config["DB_USER"]
    DB_PASSWORD = config["DB_PASSWORD"]

    SQLALCHEMY_DATABASE_URL = "postgresql://"+DB_USER+":"+DB_PASSWORD+"@"+DB_HOST+":"+DB_PORT+"/"+DB_NAME
    engine = create_engine(SQLALCHEMY_DATABASE_URL, pool_pre_ping=True)

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    Base = declarative_base()

    def generate_uuid(self):
        return str(shortuuid.ShortUUID().random(length=12))

    class Job(Base):
        __tablename__ = "jobs"
        id = Column(Integer, primary_key=True, index=True)
        uuid = Column(String, default=generate_uuid)
        genome_index = Column(String)
        result_bucket = Column(String)
        status = Column(String, default="waiting")
        status_message = Column(String)
        batch = Column(Integer)
        creation_date = Column(DateTime, default=datetime.now)
        submission_date = Column(DateTime)
        completion_date = Column(DateTime)

    dd = SessionLocal()
    
    jobs = dd.query(Job)

    if time_delta:
        one_week_ago = datetime.now() - timedelta(days=time_delta)
        jobs = jobs.filter(Job.creation_date > one_week_ago)
    
    waiting = str(jobs.filter(Job.status=="waiting").count())
    failed = str(jobs.filter(Job.status=="failed").count())
    completed = str(jobs.filter(Job.status=="completed").count())
    submitted = str(jobs.filter(Job.status=="submitted").count())

    dd.close()
    return {"time": datetime.now(), "completed": int(completed), "failed": int(failed), "waiting": int(waiting), "submitted": int(submitted)}

def check_jobs_all(
    config,
    verbose: bool = False,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
) -> Tuple[datetime, int, int, int, int]:
    """
    Retrieve counts of jobs by status within a specified date range.

    Args:
        verbose (bool): If True, prints the counts and current datetime.
        start_date (Optional[str]): Start date in "m/YYYY" format (e.g., "4/2020").
        end_date (Optional[str]): End date in "m/YYYY" format (e.g., "5/2020").

    Returns:
        Tuple containing:
            - Current datetime,
            - Count of completed jobs,
            - Count of failed jobs,
            - Count of waiting jobs,
            - Count of submitted jobs.
    """

    DB_NAME = config["DB_NAME"]
    DB_HOST = config["DB_HOST"]
    DB_PORT = config["DB_PORT"]
    DB_USER = config["DB_USER"]
    DB_PASSWORD = config["DB_PASSWORD"]

    SQLALCHEMY_DATABASE_URL = "postgresql://"+DB_USER+":"+DB_PASSWORD+"@"+DB_HOST+":"+DB_PORT+"/"+DB_NAME
    engine = create_engine(SQLALCHEMY_DATABASE_URL, pool_pre_ping=True)

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    Base = declarative_base()

    def generate_uuid(self):
        return str(shortuuid.ShortUUID().random(length=12))

    class Job(Base):
        __tablename__ = "jobs"
        id = Column(Integer, primary_key=True, index=True)
        uuid = Column(String, default=generate_uuid)
        genome_index = Column(String)
        result_bucket = Column(String)
        status = Column(String, default="waiting")
        status_message = Column(String)
        batch = Column(Integer)
        creation_date = Column(DateTime, default=datetime.now)
        submission_date = Column(DateTime)
        completion_date = Column(DateTime)

    with SessionLocal() as session:
        # Initialize the base query
        query = session.query(
            func.sum(case([(Job.status == "waiting", 1)], else_=0)).label("waiting"),
            func.sum(case([(Job.status == "failed", 1)], else_=0)).label("failed"),
            func.sum(case([(Job.status == "completed", 1)], else_=0)).label("completed"),
            func.sum(case([(Job.status == "submitted", 1)], else_=0)).label("submitted")
        )

        # If a date range is provided, parse and apply the filter
        if start_date and end_date:
            try:
                # Parse start_date as the first day of the start month
                start = datetime.strptime(start_date, "%m/%Y")
                # Parse end_date as the first day of the month after the end month
                end = datetime.strptime(end_date, "%m/%Y") + timedelta(days=31)
                end = end.replace(day=1)
            except ValueError as e:
                raise ValueError("start_date and end_date should be in 'm/YYYY' format (e.g., '4/2020')") from e

            # Apply the date range filter
            query = query.filter(
                Job.creation_date >= start,
                Job.creation_date < end
            )
        elif start_date or end_date:
            raise ValueError("Both start_date and end_date must be provided together.")

        # Execute the query
        result = query.one()

        # Extract counts, defaulting to 0 if None
        waiting = result.waiting or 0
        failed = result.failed or 0
        completed = result.completed or 0
        submitted = result.submitted or 0

        # Verbose output
        if verbose:
            print(f"Query Time: {datetime.now()}")
            print(f"waiting: {waiting}")
            print(f"submitted: {submitted}")
            print(f"failed: {failed}")
            print(f"completed: {completed}")

        return datetime.now(), completed, failed, waiting, submitted
    