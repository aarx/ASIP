from loader import get_dataframe

def summary_stats():

    df = get_dataframe()

    total = len(df)
    live = df[df["IP"] != ""].shape[0]
    known = df[df["Domain_Status"] == "Known"].shape[0]
    new = df[df["Domain_Status"] == "New"].shape[0]

    return {
        "total_domains": total,
        "live_domains": live,
        "known_domains": known,
        "new_domains": new
    }


def http_status_stats():

    df = get_dataframe()

    return df["HTTP_Status"].value_counts().to_dict()


def source_stats():

    df = get_dataframe()

    sources = df["Source"].str.split(",").explode()

    return sources.value_counts().to_dict()


def domains_per_seed():

    df = get_dataframe()

    seeds = df["Seed"].str.split(",").explode()

    return seeds.value_counts().to_dict()
