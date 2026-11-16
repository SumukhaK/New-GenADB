import time
import traceback
from solution import run_solution

TIME_LIMIT_SECONDS = 180

def evaluate():
    start_time = time.time()
    try:
        # TODO (Phase 1): Fable 5.2 will load validation data from research_draft.md specs
        # and pass inputs to run_solution()
        predictions = run_solution()
        
        elapsed = time.time() - start_time
        if elapsed > TIME_LIMIT_SECONDS:
            print(f"STATUS: TIMEOUT ({elapsed:.2f}s > {TIME_LIMIT_SECONDS}s)")
            print("SCORE: -999999.0")
            return

        # TODO (Phase 1): Fable 5.2 will implement the exact objective metric here
        # Higher SCORE must always mean better performance (negate loss/error metrics)
        score = float(predictions)

        print(f"STATUS: SUCCESS ({elapsed:.2f}s)")
        print(f"SCORE: {score:.6f}")

    except Exception as e:
        print(f"STATUS: CRASH ({e})")
        traceback.print_exc()
        print("SCORE: -999999.0")

if __name__ == "__main__":
    evaluate()
