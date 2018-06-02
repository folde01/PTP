from ptp_stream_db import Stream_DB

def main():
    db = Stream_DB()
    try:
        print("Creating ptp database...")
        db.create_db_ptp()
    except:
        print("    ...skipping database creation as it already exists.")
    try:
        print("Creating streams table...")
        db.create_table_streams()
    except:
        print("    ...skipping streams table creation as it already exists.")

if __name__ == "__main__":
    main()
    # todo: add reinitialise option as command line arg


