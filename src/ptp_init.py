from ptp_stream_db import Stream_DB
import sys

db = Stream_DB()

def create_db():
    try:
        print("Creating ptp database...")
        db.create_db_ptp()
        print("    ...done.")
    except:
        print("    ...skipping database creation as it already exists.")

def create_streams_table():
    try:
        print("Creating streams table...")
        db.create_table_streams()
        print("    ...done.")
    except:
        print("    ...skipping streams table creation as it already exists.")

def drop_streams_table():
    try:
        print("Dropping streams table...")
        db.drop_table_streams()
        print("    ...done.")
    except:
        print("    ...skipping drop as table doesn't exist.")

def init():
    create_db()
    create_streams_table()

def reinit():
    create_db()
    drop_streams_table()
    create_streams_table()

def main():
    if len(sys.argv) == 2 and sys.argv[1] == 'reinit':
        reinit()
    else:
        init()

if __name__ == "__main__":
    main()

