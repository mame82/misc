#!/usr/bin/env python3
import requests, re, json, sys
from pprint import pprint


# Small stats extractor for Google Play Apps
# (fetches data from PlayStore web page, not play-fe API)
#
# Author: MaMe82
#
# usage:   ./pstats.py <android package name>
# example: ./pstats.py com.facebook.katana

def printPlayStoreStats(package="com.google.android.gms"):
    try:
        rsp=requests.get(url="https://play.google.com/store/apps/details?id={}".format(package))
        if rsp.status_code != 200:
            raise ValueError("could not retrieve package data")

        # non greedy matching by adding '?' to '.*'
        ds6 = re.search(r"\'ds:6.*?data\:(\[.*?\]), sideChannel", rsp.content.decode("utf-8"))
        if ds6 is not None:
            m = ds6.group(1)
            rs = json.loads(m)
            appName = rs[0][0][0]
            downloadCount = rs[0][12][9]
            dc = {
                "text": downloadCount[0],
                "rounded": downloadCount[1],
                "exactCount": downloadCount[2],
                "roundedShort": downloadCount[3],
            }
            print("Google Play info for '{}'\n(package {})\n==================================\n".format(appName, package))
            print("Download count\n------------------")
            pprint(dc, width=20)

        ds7 = re.search(r"\'ds:7.*?data\:(\[.*?\]), sideChannel", rsp.content.decode("utf-8"))
        if ds7 is not None:
            m = ds7.group(1)
            rs = json.loads(m)
            rating = rs[0][6]
            ra = {
                "reviewCount": rating[2],
                "averageRating": rating[0],
                "ratingCount1stars": rating[1][1],
                "ratingCount2stars": rating[1][2],
                "ratingCount3stars": rating[1][3],
                "ratingCount4stars": rating[1][4],
                "ratingCount5stars": rating[1][5],
            }
            print("\nRatings\n------------------")
            pprint(ra)
    except Exception as e:
        print("Failed to scrape data for package '{}': {}", package, e)

printPlayStoreStats(package="com.google.android.gms" if len(sys.argv) < 2 else sys.argv[1])