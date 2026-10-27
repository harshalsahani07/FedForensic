import pandas as pd
import os

PROCESSED_PATH = 'data/processed/'

# We'll sample from the raw unscaled samples you already generated in Phase 1/2
SAMPLES = {
    'sample_benign.csv': 300,
    'sample_c2_botnet.csv': 250,
    'sample_ddos.csv': 350,
    'sample_exfiltration.csv': 200,
    'sample_lateralmovement.csv': 200,
    'sample_reconnaissance.csv': 250,
    'sample_webattack.csv': 150
}

print("Mixing test traffic from raw samples...")
dfs = []
for file, n in SAMPLES.items():
    path = os.path.join(PROCESSED_PATH, file)
    if os.path.exists(path):
        df = pd.read_csv(path)
        # Sample n rows, or all if we don't have n
        if len(df) > n:
            df = df.sample(n=n, random_state=42)
        dfs.append(df)
        print(f"  + Added {len(df)} rows from {file.replace('sample_', '').replace('.csv', '')}")

if dfs:
    # Combine and shuffle
    test_df = pd.concat(dfs, ignore_index=True)
    test_df = test_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Drop the "answer" columns to simulate raw real-world traffic
    cols_to_drop = ['label', 'threat_category', 'is_attack']
    test_df = test_df.drop(columns=[c for c in cols_to_drop if c in test_df.columns])
    
    out_path = 'test_traffic_for_upload.csv'
    test_df.to_csv(out_path, index=False)
    print(f"\n✅ Success! Created '{out_path}' with {len(test_df)} rows.")
else:
    print("❌ Error: Couldn't find sample files in data/processed/")
