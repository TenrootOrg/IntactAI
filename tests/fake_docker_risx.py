#!/usr/bin/env python3
"""A fake `docker` for tests/test_risx_to_intact.sh: just enough of the CLI to
play a risx box for risx_to_intact.sh's inventory and removal (step 7).

State is a JSON file ($FAKE_DOCKER_STATE): containers (with their compose
project, folder, status, image, volumes, networks), volumes, networks, images.
Every call is appended to $FAKE_DOCKER_LOG; `compose down` is logged with the
folder it ran in, so a test can tell which stacks were taken down and how often.
"""
import json
import os
import sys

STATE = os.environ["FAKE_DOCKER_STATE"]
LOG = os.environ.get("FAKE_DOCKER_LOG")


def load():
    with open(STATE) as f:
        return json.load(f)


def save(s):
    with open(STATE, "w") as f:
        json.dump(s, f)


def log(line):
    if LOG:
        with open(LOG, "a") as f:
            f.write(line + "\n")


def label_filter(args):
    for i, a in enumerate(args):
        if a == "--filter" and args[i + 1].startswith("label=com.docker.compose.project="):
            return args[i + 1].split("=", 2)[2]
    return None


def main(a):
    s = load()
    cont = {c["id"]: c for c in s["containers"]}
    if a[:2] == ["ps", "-a"] and "--format" in a and "{{.ID}}|" in a[a.index("--format") + 1]:
        for c in s["containers"]:
            print("|".join([c["id"], c["name"], c.get("project", ""), c.get("wd", ""), c["status"]]))
        return 0
    if a[0] == "inspect":
        if a[1] == "-f":
            for cid in a[3:]:
                c = cont.get(cid)
                if c:
                    print(f'{c["image"]}|{"".join(v + "," for v in c.get("vols", []))}|'
                          f'{"".join(n + "," for n in c.get("nets", []))}')
            return 0
        return 0 if a[1] in cont else 1
    if a[0] == "rm":
        s["containers"] = [c for c in s["containers"] if c["id"] != a[-1]]
        save(s)
        return 0
    if a[0] == "volume":
        names = {v["name"]: v for v in s["volumes"]}
        if a[1] == "ls":
            p = label_filter(a)
            for v in s["volumes"]:
                if p is not None and v.get("project") != p:
                    continue
                if "dangling=true" in a and not v.get("dangling"):
                    continue
                print(v["name"])
            return 0
        if a[1] == "inspect":
            return 0 if a[2] in names else 1
        if a[1] == "rm":
            s["volumes"] = [v for v in s["volumes"] if v["name"] != a[-1]]
            save(s)
            return 0
    if a[0] == "network":
        names = {n["name"] for n in s["networks"]}
        if a[1] == "ls":
            p = label_filter(a)
            for n in s["networks"]:
                if p is None or n.get("project") == p:
                    print(n["name"])
            return 0
        if a[1] == "inspect":
            return 0 if a[2] in names else 1
        if a[1] == "rm":
            s["networks"] = [n for n in s["networks"] if n["name"] != a[-1]]
            save(s)
            return 0
    if a[0] == "images":
        for i in s["images"]:
            if "dangling=true" in a and not i.get("dangling"):
                continue
            print(f'{i["id"]}|{i["ref"]}' if "--format" in a else i["id"])
        return 0
    if a[0] == "image":
        imgs = {i["id"]: i for i in s["images"]}
        if a[1] == "inspect":
            if a[2] == "-f":
                for iid in a[4:]:
                    if iid in imgs:
                        print(imgs[iid]["ref"] if "RepoTags" in a[3] else imgs[iid]["size"])
                return 0
            return 0 if a[2] in imgs else 1
        if a[1] == "rm":
            s["images"] = [i for i in s["images"] if i["id"] != a[-1]]
            save(s)
            return 0
    if a[0] == "system" and a[1] == "df":
        print(f'Build Cache|{s.get("build_cache", "0B")}')
        return 0
    if a[0] == "builder" and a[1] == "prune":
        log("builder prune")
        s["build_cache"] = "0B"
        save(s)
        return 0
    if a[0] == "compose":
        if "down" in a:
            cwd = os.getcwd()
            log(f"compose down {cwd}")
            gone = [c for c in s["containers"] if c.get("wd") == cwd]
            projs = {c.get("project") for c in gone} | {os.path.basename(cwd)}
            s["containers"] = [c for c in s["containers"] if c.get("wd") != cwd]
            s["volumes"] = [v for v in s["volumes"] if v.get("project") not in projs]
            s["networks"] = [n for n in s["networks"] if n.get("project") not in projs]
            save(s)
        return 0
    return 0


sys.exit(main(sys.argv[1:]))
