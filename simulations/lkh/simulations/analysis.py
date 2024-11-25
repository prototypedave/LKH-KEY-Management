import matplotlib.pyplot as plt
import pandas as pd 
import numpy as np 

"""
    Read csv files for data retrieval - Deletion Delay
    @attribute: DelDelayFlatLg - results of removing a node from the server (Flat network 1024)
    @attribute: DelDelayFlatMd - results of removing a node from the server (Flat network 128)
    @attribute: DelDelayFlatSm - results of removing a node from the server (Flat network 16)
"""
DelDelayFlatLg = pd.read_csv("flat/results/delDelay-1024.csv", header=None, names=["time", "nodes", "msg"])
DelDelayFlatMd = pd.read_csv("flat/results/delDelay-128.csv", header=None, names=["time", "nodes", "msg"])
DelDelayFlatSm = pd.read_csv("flat/results/delDelay-16.csv", header=None, names=["time", "nodes", "msg"])

# Sort
DelDelayFlatLg = DelDelayFlatLg.sort_values(by="nodes")
DelDelayFlatMd = DelDelayFlatMd.sort_values(by="nodes")
DelDelayFlatSm = DelDelayFlatSm.sort_values(by="nodes")

DelDelayLKHLg = pd.read_csv("lkh/results/delDelay-1024.csv", header=None, names=["time", "nodes", "msg"])
DelDelayLKHMd = pd.read_csv("lkh/results/delDelay-128.csv", header=None, names=["time", "nodes", "msg"])
DelDelayLKHSm = pd.read_csv("lkh/results/delDelay-16.csv", header=None, names=["time", "nodes", "msg"])

# Sort
DelDelayLKHLg = DelDelayLKHLg.sort_values(by="nodes")
DelDelayLKHMd = DelDelayLKHMd.sort_values(by="nodes")
DelDelayLKHSm = DelDelayLKHSm.sort_values(by="nodes")

"""
    Read csv files for data retrieval - Distribution Delay
    @attribute: DistDelayFlatLg - results of distributing keys from the server to nodes(Flat network 1024)
    @attribute: DistDelayFlatMd - results of distributing keys from the server to nodes (Flat network 128)
    @attribute: DistDelayFlatSm - results of distributing keys from the server to nodes (Flat network 16)
"""
DistDelayFlatLg = pd.read_csv("flat/results/distDelay-1024.csv", header=None, names=["time", "nodes", "msg"])
DistDelayFlatMd = pd.read_csv("flat/results/distDelay-128.csv", header=None, names=["time", "nodes", "msg"])
DistDelayFlatSm = pd.read_csv("flat/results/distDelay-16.csv", header=None, names=["time", "nodes", "msg"])

# Sort
DistDelayFlatLg = DistDelayFlatLg.sort_values(by="nodes")
DistDelayFlatMd = DistDelayFlatMd.sort_values(by="nodes")
DistDelayFlatSm = DistDelayFlatSm.sort_values(by="nodes")

DistDelayLKHLg = pd.read_csv("lkh/results/distDelay-1024.csv", header=None, names=["time", "nodes", "msg"])
DistDelayLKHMd = pd.read_csv("lkh/results/distDelay-128.csv", header=None, names=["time", "nodes", "msg"])
DistDelayLKHSm = pd.read_csv("lkh/results/distDelay-16.csv", header=None, names=["time", "nodes", "msg"])

# Sort
DistDelayLKHLg = DistDelayLKHLg.sort_values(by="nodes")
DistDelayLKHMd = DistDelayLKHMd.sort_values(by="nodes")
DistDelayLKHSm = DistDelayLKHSm.sort_values(by="nodes")

"""
    Read csv files for data retrieval - Key generation delay
    @attribute: KeyDelayFlatLg - results of generating keys (Flat network 1024)
    @attribute: KeyDelayFlatMd - results of generating keys (Flat network 128)
    @attribute: KeyDelayFlatSm - results of generating keys (Flat network 16)
"""
KeyDelayFlatLg = pd.read_csv("flat/results/keyDelay-1024.csv", header=None, names=["time", "nodes"])
KeyDelayFlatMd = pd.read_csv("flat/results/keyDelay-128.csv", header=None, names=["time", "nodes"])
KeyDelayFlatSm = pd.read_csv("flat/results/keyDelay-16.csv", header=None, names=["time", "nodes"])

# Sort
KeyDelayFlatLg = KeyDelayFlatLg.sort_values(by="nodes")
KeyDelayFlatMd = KeyDelayFlatMd.sort_values(by="nodes")
KeyDelayFlatSm = KeyDelayFlatSm.sort_values(by="nodes")

KeyDelayLKHLg = pd.read_csv("lkh/results/keyDelay-1024.csv", header=None, names=["time", "nodes"])
KeyDelayLKHMd = pd.read_csv("lkh/results/keyDelay-128.csv", header=None, names=["time", "nodes"])
KeyDelayLKHSm = pd.read_csv("lkh/results/keyDelay-16.csv", header=None, names=["time", "nodes"])

# Sort
KeyDelayLKHLg = KeyDelayLKHLg.sort_values(by="nodes")
KeyDelayLKHMd = KeyDelayLKHMd.sort_values(by="nodes")
KeyDelayLKHSm = KeyDelayLKHSm.sort_values(by="nodes")

"""
    Read csv files for data retrieval - 
    @attribute: KeyDelayFlatLg - results of generating keys (Flat network 1024)
    @attribute: KeyDelayFlatMd - results of generating keys (Flat network 128)
    @attribute: KeyDelayFlatSm - results of generating keys (Flat network 16)
"""
LatencyFlatLg = pd.read_csv("flat/results/latency-1024.csv", header=None, names=["time"])
LatencyFlatMd = pd.read_csv("flat/results/latency-128.csv", header=None, names=["time"])
LatencyFlatSm = pd.read_csv("flat/results/latency-16.csv", header=None, names=["time"])

LatencyLKHLg = pd.read_csv("lkh/results/latency-1024.csv", header=None, names=["time"])
LatencyLKHMd = pd.read_csv("lkh/results/latency-128.csv", header=None, names=["time"])
LatencyLKHSm = pd.read_csv("lkh/results/latency-16.csv", header=None, names=["time"])

def regroup(comm, value):
    group_size = len(comm) // value
    if group_size == 0:
        avg_comm = pd.DataFrame({"time": [comm["time"].mean()] * value})
    else:
        comm["group"] = pd.cut(comm.index, bins=value, labels=False)
        avg_comm = comm.groupby("group")["time"].mean().reset_index(drop=True)
    return avg_comm

LatencyFlatLg = regroup(LatencyFlatLg, 1024)
LatencyFlatMd = regroup(LatencyFlatMd, 128)
LatencyFlatSm = regroup(LatencyFlatSm, 16)
LatencyLKHLg = regroup(LatencyLKHLg, 1024)
LatencyLKHMd = regroup(LatencyLKHMd, 128)
LatencyLKHSm = regroup(LatencyLKHSm, 16)

"""
    COMPARISON PLOTS
    @method: Delay : Plots cost of removing a node
    @method: Cost  : Plots cost in terms of number of overheads
    @method: Latency: Plots the time taken to transmit messages from one node to the next
"""

def plot_delay(df1, df2, label1, label2, ylabel, xlabel, title, dir):
    fig, ax = plt.subplots()
    ax.plot(df1["nodes"], df1["time"] * 1000, label=label1)
    ax.plot(df2["nodes"], df2["time"] * 1000, label=label2)
    ax.set_ylabel(ylabel)
    ax.set_xlabel(xlabel)
    ax.set_title(title)
    ax.legend()
    ax.grid(True)
    plt.savefig(dir+"/"+title+".png")
    plt.close()

def plot_cost(df1, df2, label1, label2, ylabel, xlabel, title, dir):
    fig, ax = plt.subplots()
    ax.plot(df1["nodes"], df1["msg"], label=label1)
    ax.plot(df2["nodes"], df2["msg"], label=label2)
    ax.set_ylabel(ylabel)
    ax.set_xlabel(xlabel)
    ax.set_title(title)
    ax.legend()
    ax.grid(True)
    plt.savefig(dir+"/"+title+".png")
    plt.close()

def plot_latency(df1, df2, label1, label2, ylabel, xlabel, title, dir):
    fig, ax = plt.subplots()
    ax.plot(df1.index, df1, label=label1)
    ax.plot(df2.index, df2, label=label2)
    ax.set_ylabel(ylabel)
    ax.set_xlabel(xlabel)
    ax.set_title(title)
    ax.legend()
    ax.grid(True)
    plt.savefig(dir+"/"+title+".png")
    plt.close()

plot_delay(DelDelayFlatLg, DelDelayLKHLg, "flat key-1024", "lkh-1024", "Delay (ms)", "No of nodes", "Flat Key vs LKH Key 1024 Members Delay in Key Distribution after Node leave", "deletion_delay")
plot_delay(DelDelayFlatMd, DelDelayLKHMd, "flat key-128", "lkh-128", "Delay (ms)", "No of nodes", "Flat Key vs LKH Key 128 Members Delay in Key Distribution after Node leave", "deletion_delay")
plot_delay(DelDelayFlatSm, DelDelayLKHSm, "flat key-16", "lkh-16", "Delay (ms)", "No of nodes", "Flat Key vs LKH Key 16 Members Delay in Key Distribution after Node leave", "deletion_delay")

plot_cost(DelDelayFlatLg, DelDelayLKHLg, "flat key-1024", "lkh-1024", "No of messages", "No of nodes", "Flat Key vs LKH Key 1024 Members Messages transmitted after Node leave", "deletion_delay")
plot_cost(DelDelayFlatMd, DelDelayLKHMd, "flat key-128", "lkh-128", "No of messages", "No of nodes", "Flat Key vs LKH Key 128 Members Messages transmitted after Node leave", "deletion_delay")
plot_cost(DelDelayFlatSm, DelDelayLKHSm, "flat key-16", "lkh-16", "No of messages", "No of nodes", "Flat Key vs LKH Key 16 Members Messages transmitted after Node leave", "deletion_delay")

plot_delay(DistDelayFlatLg, DistDelayLKHLg, "flat key-1024", "lkh-1024", "Delay (ms)", "No of nodes", "Flat Key vs LKH Key 1024 Members Delay in Key Distribution after Node join", "key_distribution_delay")
plot_delay(DistDelayFlatMd, DistDelayLKHMd, "flat key-128", "lkh-128", "Delay (ms)", "No of nodes", "Flat Key vs LKH Key 128 Members Delay in Key Distribution after Node join", "key_distribution_delay")
plot_delay(DistDelayFlatSm, DistDelayLKHSm, "flat key-16", "lkh-16", "Delay (ms)", "No of nodes", "Flat Key vs LKH Key 16 Members Delay in Key Distribution after Node join", "key_distribution_delay")

plot_cost(DistDelayFlatLg, DistDelayLKHLg, "flat key-1024", "lkh-1024", "No of messages", "No of nodes", "Flat Key vs LKH Key 1024 Members Messages transmitted after Node join", "key_distribution_delay")
plot_cost(DistDelayFlatMd, DistDelayLKHMd, "flat key-128", "lkh-128", "No of messages", "No of nodes", "Flat Key vs LKH Key 128 Members Messages transmitted after Node join", "key_distribution_delay")
plot_cost(DistDelayFlatSm, DistDelayLKHSm, "flat key-16", "lkh-16", "No of messages", "No of nodes", "Flat Key vs LKH Key 16 Members Messages transmitted after Node join", "key_distribution_delay")

plot_delay(KeyDelayFlatLg, KeyDelayLKHLg, "flat key-1024", "lkh-1024", "Delay (ms)", "No of nodes", "Flat Key vs LKH Key 1024 Members Delay in Key Generation", "key_generation_delay")
plot_delay(KeyDelayFlatMd, KeyDelayLKHMd, "flat key-128", "lkh-128", "Delay (ms)", "No of nodes", "Flat Key vs LKH Key 128 Members Delay in Key Generation", "key_generation_delay")
plot_delay(KeyDelayFlatSm, KeyDelayLKHSm, "flat key-16", "lkh-16", "Delay (ms)", "No of nodes", "Flat Key vs LKH Key 16 Members Delay in Key Generation", "key_generation_delay")

plot_latency(LatencyFlatLg, LatencyLKHLg, "flat key-1024", "lkh-1024", "Delay (s)", "", "Flat Key vs LKH Key 1024 Members Latency", "latency")
plot_latency(LatencyFlatMd, LatencyLKHMd, "flat key-128", "lkh-128", "Delay (s)", "", "Flat Key vs LKH Key 128 Members Latency", "latency")
plot_latency(LatencyFlatSm, LatencyLKHSm, "flat key-16", "lkh-16", "Delay (s)", "", "Flat Key vs LKH Key 16 Members Latency", "latency")
