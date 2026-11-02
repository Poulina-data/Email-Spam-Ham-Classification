import pandas as pd

def load_data(path):
    df = pd.read_csv(path, encoding="latin-1")
    df = df[["v1", "v2"]]
    df.columns = ["label", "email_text"]

    return df