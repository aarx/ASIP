import pandas as pd

DATA_PATH = "data/final_output.csv"

df = pd.read_csv(DATA_PATH)

# normalize empty fields
df["IP"] = df["IP"].fillna("")
df["HTTP_Status"] = df["HTTP_Status"].fillna("")
df["Source"] = df["Source"].fillna("")
df["Seed"] = df["Seed"].fillna("")

def get_dataframe():
    return df
