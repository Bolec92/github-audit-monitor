from app import RUN_ON_START, execute_snapshot, scheduler_loop

if __name__ == "__main__":
    if RUN_ON_START:
        execute_snapshot()
    scheduler_loop()
