"""
Example add-on how to decompress traffic for 'graph.facebook.com/graphql', which arrives ZSTD-compressed
with a CUSTOM DICTIONARY TRAINED BY FACEBOOK.

The purpose of this add-on is not only to demo how zstd decompression with custom dicts could be achieved,
but also to emphasize the reasons on why "This is a bad idea".

Reasons not to decompress ZSTD with custom dicts:

The custom dicts are context specific (target service, target endpoint, dict version etc etc) and would have
to be available for all possible use-case. This is almost impossible to do from the persepctive of a central
interception proxy, which has only limited awareness of the setup of the requesting clients (in fact, the
proxy can't no the proper decompression dictionary to use, unless it gets transmitted along - doing so would
counter the effect of dictionary based ZSTD compression and is unlikely to happen in the wild).
Also, this demo should show, that there is not enough "wire information" to safely conclude on the proper dictionary
to use. This addon is limited to the following criteria, in order to deploy decompression (with a hardcoded dcitionary):

- request endpoint is 'https://graph.facebook.com/graphql'
- a header indicating usage of ZSTD compression is included in the response ('content-encoding: x-fb-dz')
- a header indicating usage of ZSTD dictionary number '1' for this endpoint is used ('x-fb-dz-dict: 1')

Even with all this criteria applied, it could not relaibly determined which dictionary to use. This is because
the dictionary gets never transmitted "over the wire". Instead, it is hardcoded into the client (from where I dumped it)
and thus depends on the client version (facebook updates those dictionaries, as they are trained based on API traffic).
This again means, without knowing the exact client version of the Facebook app in use, no safe conclusion could be drawn
on the correct dictionary to use.

So this example is more like "doing it the hard way", which you shouldn't. The "easy way" would be to alter the
'accept-encoding' header to avoid responses compressed with 'zstd', at all.
I left a comment on how to do this (for Facebook traffic) in the following mitmproxy github issue:

https://github.com/mitmproxy/mitmproxy/issues/4394#issuecomment-957459382

Run this add-on with:
# mitmproxy -s /path/to/fb-zstd.py
"""

from mitmproxy import flowfilter
from mitmproxy import ctx, http
from base64 import b64decode
# while 'mitmproxy.net.encoding' has ZSTD support, it does not support traiing dictionaries and cannot be used
import zstandard

# ZSTD dictionary #1, dumped from libcoldstart.so of com.facebook.katana v342.0.0.37.119 (arm32)
FB_ZSTD_DICT1 = "N6Qw7AEAAAA3ELAB6wYwDMMwDMMwDMPAQLTtJqIhEthgIyVRJnrHrmjbnSaaDVa0PWw/mZmZmSl/eP6uw3CBH9MCAAgMCsXC8ZBUMia2AwQgwRAVDhmSkAvJg+FgLBKIg8FQMBhFQRAEQRCDQRCEUSBJmbNsAAAEMWhDiTwaBTmMgxBCChmDkDRzAAAAAQAAAAQAAAAIAAAARTJORGtzdG9yeTEwNzIxMDY3NjM0Njg1NjQwN3RvcF83ODY0NmVhdG9yWTJOak14TVRNakV3TWpjd003OVwiLFwiaXAiOjAsInRleHRfZGVsaWdodHNfdWNlZCI6ImRhdGEiOnsiMjAifX0sInNwb25zb3JfIm1ham9yX3ZlcnNpb257ImlkIjoiZW50X3RlZWRiYWNrIjp7Il0sImZvY3VzZWRfY29tbWVudF9pZCI6WyJZMjl0YldWdWREbzAwMDB5TmpreE9UazVOalEyTSwiY29tbWVudF9jb3VudF9yZTVTXCI+XHUwMDNDc2IxLTIuZm5hLmZiMTQ3OFwiLFwicG9zdF9vbGVcIjoxLFwiZWxhdGlvbnNuZ2xpc3siX190eXBlbmFtZSI6ImRcIjpcIjFcIjAwMDA2XCIgRkJFbmNvZGluZ1RhZz1cImRhc2hfdjBfMjU2X2NyZl8yM19tYWluXzMuMF9mcmFnXzJfdHRhY2hsb2NrZWRfYnlfdmlld2VyIjpmYWxzZWluZ2xlX2ZyaWVuZF9zdG9yaWVzIjpmYWxzZX0sInJlZmVyaWRlby5mInRleHQiOiJkZW9fY3RpbWVfbXMiOjIwMCwiaXNfdWRpb1wiPlx1MDAzQ0EwMDNDXC9CYXNlVVJMPlx1MDAzQ1NlZ21lbnRCYXNlIGluZGV4b2xsX2RlZ3JlZXMiOjAsIjQ0ODEwMDAwMDAwMDAwIiwiaW5lYXJfdmJfbWF0dXJlX2NvbnRlbnRfcmF0aW5nX2ludCI6bnVsbCwiZmJfbWF0dXJlX2NvbnRlbnRfcmF0aW5nX3RleHQiOm51bGwsInNob3ciOm51bGwsIiwidmlkZW9fcGhlcmljYWxQbGF5YWJsZVVybFNkU3RyaW5nIjpudWxsLCJzcGhlcmljYWxQbGF5YWJsZVVybEhkU3RyaW5nIjpudWxsLCJzcGFuX2JhZGdlX3N0YXR1cyI6d2lkdGhfZGVncmVlcyI6MCwiYW5nZUV4YWN0PVwidHJ1ZVwiIGluZGV4UmFuZ2U9XCIwODAtOTczXCIgRkJGaXJzdFNlZ21lbnRSYW5nZT1cIjAwMDAwMDQwNVwiIEZCU2Vjb25kU2VnbWVudFJhbmdlPVwiMDAwMDYtMjU2MzNcIj5cdTAwM0NJbml0aWFsaXphdGlvbiByYW5nZT1cIjAtMDgxXCJcLz5cdTAwM0NcL1NlZ21lbnRCYXNlPlx1MDAzQ1wvUmVwcmVzZW50YXRpb24+XHUwMDNDXC8nbXF0dF9sYXJ1YnNjcmliZXJfZGF0YQAlaXJpc190YXJ0c1dpdGhTQVA9XCIxXCI+XHUwMDNDUmVwcmVzZW50YXRpb24gaWQ9XCIwMDA2NDI3MTg2MDQ0NzNhZFwiIG1pbWVUeXBlPVwiZXN0AgAAX3R5cGVuYW1lIjoic2FtcGxpbmcCMG1xdHRfaWRlb19waXZvdCI6W10sImludGVncmF0ZWRfbG91ZG5lc3MiOi0ic3RhdGljXCIgbWVkaWFQcmVzZW50YXRpb25EdXJhdGlvbj1cIlBUMEgwTTAuMDg1U1wiIG1heFNlZ21lbnREdXJhdGlvbj1cIlBUMEgwTTIuMDAyU1wiIHByb2ZpbGVzPVwidXJuOm1wZWc6ZGFzaDpwcm9maWxlOmlzb2ZmLW9uLWRlbWFuZDoyMDExLGh0dHA6XC9cL2Rhc2hpZi5vcmdcL2d1aWRlbGluZXNcL2Rhc2gyNjRcIj5cdTAwM0NQZXJpb2QgZHVyYXRpb249XCJQVDBIME19LCJ2aWRlb19wcm90b2NvbF9wcm9wcyI6bnVsbCwiaXNfbGl2ZV97ImlkIjoiOTA4NTYzNDU5MjM2NDY2Iiwia2V5Ijo3fWVcIiBzdWJzZWdtZW50aWRlb19jYXB0aW9uc186ZmFsc2UsInJ0Y19wbGF5YmFja2RhcHRhdGlvblNldCBzZWdtZW50QWxpZ25tZW50PVwidHJ1ZXJpY2FsUHJlZmVycmVkRm92Ijo2MCwiZ3VpZGVkX3RvdXIiOnsia2V5ZnJhbWVzIjpbXX0sImhvdHNwb3RfZWZmZWN0IjpudWxsLCJlbmFibGVfZm9jdXMiOmZhbHNlLCJvZmZfZm9jdXNfbGV2ZWwiOjEsIm9mZl9mb2N1c19sZXZlbF9kYiI6MCwiZm9jdXN1cmF0aW9uIHNjaGVtZUlkVXJpPVwidXJuOm1wZWc6ZGFzaDoyMzAwMzozOmF1ZGlvX2NoYW5uZWxfY29uZmlndXJhdGlvbjoyMDExXCIgdmFsdWU9XCIyXCJcLz5cdTAwM0NCYXNlVVJMPmh0dHBzOlwvXC9cdTAwM0NzdGF0ZSI4fV19LCJpc19zcGhlcmljYWwiOmZhbHNlLCJwaG90b3VkaW9cL21wNFwiIGNvZGVjcz1cIm5rX3R5cGUiOmVuZm9yY2VfbHNfcmVnaW9uX2hpbnQwHW1xdHRfb21tZXJjaWFsX2JyZWFrIjpmYWxzZSwiZWxpZ2libGVfYWRfZm9ybWF0cyI6W10sImluc3RyZWFtX3ZlbnRzACFvbW5pc3RvcmVfb3ZlcnJpZGVkaW9DaGFubmVsQ29uZmlydWUsInN1YnNyZWFzb24CEmFsbF9lbXBsb3llZXNfbXF0dAIdb21uaXN0b3JlX3Jlc25hcHNob3RfcmVzcG9uc2UCHm9tbmlzdG9yZV9zbmFwc2hvdF9sYXRlc3RfdGllcgIbb21uaXN0b3JlX3NuYXBzaG90X2Rldl90aWVyYW1wbGluZ1JhdGU9XCJzY3ViYQIdbXF0dF9ub19zZW5kcGluZ19vbl9zdWJzY3JpYmUCH21xdHRfZW5hYmxlX2VuZHBvaW50X2V2ZW50c19sb2cCJG1xdHRfZW5hYmxlX2VuZHBvaW50X2V2ZW50c19oaXZlX2xvZwIad2F0ZXJmYWxsX21lc3NhZ2VfbGlmZXRpbWUCH3dhdGVyZmFsbF9ORFU9IiwiY2FjaGVfaWQiOiJNMDAwMDAwMDAwMDAwRFl5TTBZek1ERTAwMHN6T1RBME9ERXdOajAyTjBrek5EVTBNemt3TjBneE1EWTBOalE1TXowMU96RTFOekEwTTAwM05UYz0iLCJoZWFkZXJfYWNjZW50X3RjX2Jyb2FkY2FzdHdzX3B1Ymxpc2hfdG9fY2xpZW50X2NhY2hlAChvbW5pc3RvcmVfY3Jvc3Nfc3RhY2tfc2N1YmFfbG9nZ2luZx1ydGlfcGxhdGZvcm1fcHA0YS40MC41XCIgYXVkaW8iaGFzX3RvcF9mcmllbmRzZXNzYWdlX2xpZmV0aW1lX2hpdmUAF21xdHRfZW5hYmxlX2JsYWRlcnVubmVyAhltcXR0X3NlciIsImlkIjoiMQIhcnRpX3ZpZXdlcl9wcmVzZW5jZV9sb2dnaW5ndG9wX3NlbmRpbmdfb2xkX3N1YnNjcmliZXJfZGF0YQIPb25ldmNfbWlncmF0aW9uAg9pbmJveF9taWdyYXRpb24CIW9tbmlzdG9yZV9yZXNlbmRfZnVsbF9wdWxsX2N1cnNvcgAebXF0dF9tZXNzYWdlc19xdWV1ZV9vbl9nZW5lcmljAhZtcXR0X2R1bW15X2drX2Zvcl8wLCJpc19sb29waW5nIjpmYWxzZSwiaXN0IjoiXHUwMDNDP3htbCB2ZXJzaW9uPVwiMS4wXCI/PlxuXHUwMDNDTVBEIHhtbG5zPVwidXJuOm1wZWc6ZGFzaDpzY2hlbWE6bXBkOjIwMTFcIiBtaW5CdWZmZXJUaW1lPVwiUFQxLjUwMFNcIiB0eXBlPWlkZW9fYWRfYnJlYWtzIjpbXSwicHJlX3JvbGxfYWRfYnJlYWsiOm51bGwsImlzX3ZpZXdhYmlsaXR5X2xvZ2dpbmdfZWxpZ2libGUiOmZhbHNlLCJwb2xsaW5nZW5lcmljXywiaW5pdGlhbF92aWV3X2VuY2VfY29uc2lzdGVuY3lfbG9nK2ZiNGFfbXF0dF9wcmVzZW5jZV9jcHVfYmF0dGVyeV9vcHRpbWl6YXRpb24wGG9tbmlzdG9yZV9iYXRjaF9zbmFwc2hvdAIab21uaXN0b3JlX2hhbmRsZV9zdWJzY3JpYmUCGG9tbmlzdG9yZV9kZWx0YV9tcXR0X2xvZwIobXF0dF9ub191bm5lY2Vzc2FyeV9yaWNoX3ByZXNlbmNlX3VwZGF0ZQIdb21uaXN0b3JlX3NlbmRfZGVsdGFfcmVzcG9uc2UCMW1xdHRfc2tpcF9zZW5kaW5nX3ByZXNlbmNlX3JlY2VpdmVyX2luX2JhY2tncm91bmQbcHlsb25fbG9jYWxfcmVwbGljYV9ydGNfcDJwAA9tcXR0X2RpcmVjdF9ydGMCIWlyaXNfc2VuZF9pbmcCIG1xdHRfL1BlcmlvZD5cdTAwM0NcL01QRD5cbiIsImNhbl92aWV3ZXJfbmRfY3Vyc29yIjphbHNlLCJhYm91dF9jb250ZXh0IjpbZm9zIjpbeyJfX3R5cGVuYW1lIjoiQgEabXVsdGlnZXRHYXRlS2VlcGVySW5mb0J5SWQLAAFsMDAwMDC9LRtBhRRtcXR0X3VzZXJzX29uX2xhdGVzdAIdcmVhbHRpbWVfaW5mcmFfbmVjdGFyX2xvZ2dpbmcCKHJlYWx0aW1lX2luZnJhX25lY3Rhcl9yZWxhYmlsaXR5X2xvZ2dpbmcCK3JlYWx0aW1lX2luZnJhX25lY3Rhcl9tcXR0X2VuZHBvaW50X2xvZ2dpbmcwHG1lc3Nlbmdlcl9wcmVfYWRkX3AycF90b3BpY3MAKW1xdHRfYXV0b19nZW5lcmF0ZV9kZWxpdmVyeV9yZWNlaXB0X2JhdGNoABxyZWFsdGl9fX0sImV4cG9ydHMiOnsic2hvcnRfdGVybV9jYWNoZV9rZXlfc3RvcnlzZXQiOlsiMDgifSwiaGlkZWFibGVfdG9rZW4iOiJNejAwMDBDME1EMDAwREN4TkRJeE4waHp6U3NKTGtrc0tTMTJMMDAwMDAwMDAwMDAwMC1xcktzek5EMHhNVE0wTkRJd00wMDAwMDBzcXpPb0F3QSIsInd3d1VSTCI6Imh0dHBkYXB0YXRpb25TZXRlYXNvbl9hbmRfZXBpc29kZV9zdHJpbmciOmRlZXBfZGl2ZV9hdmFpbGFiaWxpdHkiOnBzeW5jX2ludGVydmFsAhNtcXR0X21yeF9leHBlcmltZW50cmFjZV9lbmFibGVkIjp1bGwsImxpdmVfZXdlcl9zaGFyZSI6dHJ1ZSwicGxheW9nX2FsbF9yZWNpcGllbnRfbXF0dAIjbXF0dF9sYXJnZV9wYXlsb2FkX2JhdGNoaW5nX3N1cHBvcnRyZXNlbmNlX3siaWQiOiI0Nzg1NDczMTU2NTAxNDQiLCJrZXkiOjN9LCJtZWRpYSI6J20gY29uY2VybmVkIGFib3V0IHRoaXMgcG9zdCJ9LCJudWxsLCJpbnN0cmVhbV90cmFuc2l0aW9uX3NjcmVlbjhcIixcInBhZ2VfaWRcIjpcIjQxMDBcIiBzdGFydFdpdGhTQVA9XCIxXCIgYmFuZHdpZHRoMTkzMzE5NSIsInJhbmdlcyI6W10sImRlbGlnaHRfcmFuZ2VzIjpbXSwiYWdncmVnYXRlZF9yYW5nZXMiOltdfSwidHlwZSI6InN0cmluZyJ9LHsia2V5IjoibGF5b3V0X3giLCI6e1wiaXNTaGFyZVwiOjAsXCJvcmlnaW5hbCx7ImlkIjoiMTE1OTQwNjU4NzY0OTYzIiwia2V5Ijo0fXJlX2hpZGRlbiI6ZmFsc2UsInRyYWNraW5ncnVlLCJlZHVjYXRpb24sInJhbmtpbmdfc2lnbmFscyI6W10sInByb21wdF9jb21wb3NpdGlvbiI6eyJlbGFkZXJ1bm5l-cgImbWVzc2VuZ2VyXzA3NjAwMDAwMDA5XCJdfSxcInJvbGVcIjoxLFwic2xcIjo1LFwidGFyZ2V0c1wiOlt7XCJhY3Rvcl9pZFwiOlwibm9vemUgMDByYmFyYSBmb3IgMzAgZGF5cyJ9LCJzdWJ0aXRsZSI6eyJ0ZXh0Ijoic3RyZWFtX3Nwb25zb3JfcGFnZSI6b2xsYWdlUGhvdG9BdHRhY2htZW50U3R5bGVJbmZvIiwibGF5b3V0X3giOjAsImxheW91dF95IjowLCJsYXlvdXRfd2lkdGgiOjEsImVwb3J0Ijp0cnVlLCIiTVRVM01EMDBNemMwMDAwMDAwMDAwMDB6TjBVM09qTTZORGMwTTBJd01qZzJNakF6TzBVME5UVXpNem93T2pZM05EMDBNVFUwTTAwd05UQXdOVFF4TjAwPSJdfSwiZXh0ZW5zaW9ucyI6eyJmdWxmaWxsZWRfcGF5bG9hZHMiOlt7ImxhYmVsIjoiRGVmZXJyYWJsZUZpZWxkc0ZvclN0cmVhbWluZ0ZyYWdtZW50IiwicGF0aCI6WyJ2aWV3ZXIiLCJuZXdzX2ZlZWQiXX1dLCJyZXNvbHZlZF9wYXJhbXMiOnsiYWZ0ZXJfaG9tZV9zdG9yeV9wYXJhbSI6Ik1UVTNNRHNlciIsImlkIjoiMTAwMG9jYWxlcyI6W10sImNyZWF0ZWRfdGltZSI6MTU3MDAwMDA0OSwiY3JlYXRpb25fc3RvcnkiOnsiaWQib3N0T3duZXJJRFwiOjB9LFwicHNuXCI6XCJFbnRTdGF0dXNDcmVhdGlvblN0b3J5XCIsXCJwb3N0X2NvbnRleHRcIjp7XCJvYmplY3RfZmJ0eXBlXCI6MjY2LFwicHVibGlzaF90aW1lXCI6MTU3MDAwMDIwMixcInN0b3J5X25hbWVcIjpcIkVudFN0YXR1c0NyZWF0aW9uU3RvcnlcIixcInN0b3J5X2ZiaWRcIjpbXCJydWV9fX0seyJvZ19kaXNjb25uZWN0cm9maWxlLnBocD9pZD0xMDAwMDAwMDY1MDI3NDgiLCJpc19jdXJyZW50bHlfbGl2ZSI6ZmFsc2UsImNhbl92aWV3ZXJfbWVzc2FnZSI6dHJ1ZSwiaXNfbWVzc2FnZV9ibG9ja2VkX2J5X3ZpZXdlciI6ZmFsc2UsImlzX3ZpZXdlcl9mcmllbmQiOnRydWUsInNob3VsZF91bV9jaGFpbmluZ19wcmV2aWV3X3ZpZGVvcyI6MH0sInN0b3J5X2ljb25faW5mbyI6bnVsbCwiaXNfc2VlX2ZpcnN0X2J1bXBlZCI6ZmFsc2UsInNlZV9maXJzdF9hY3RvcnMiOltVTVBfVU5SRUFEIiwicmFua2luZ193ZWlnaHQiOjAwMDAwMDAzMzIwMzEyNSwiY3Vyc29yIjoiTVRVM01EMDBOalEwT1RveE5UY3dNMEUyTkQwNU9qRTBPaTB4TURFMTBEYzVNRGN4TjBjeU1qY3hORE14T2pBNk5qYzBORDAxTjBjNU5EQTRNREF5TTAwek1RPT0iLCJmZWF0dXJlc19tZXRhIjoie1wic3ViamVjdF90eXBlXCI6MCxcIndhc19zZWVuXCI6MCxcInN0b3J5X3JhbmtpbmdfdGltZVwiOjE1NzAwMDA0NDksXCJ2X3ZpZXdlZFwiOi0wMDAyLFwicF9jb21tZW50XCI6MDAwMixcInZfY29tbWVudFwiOjA2MjUsXCJwX29iY1wiOjAsXCJ2X29iY1wiOjAsXCJwX2xpa2VcIjowMDA0NCxcInZfbGlrZVwiOjE1MTAsXCJidW1wX3JlYXNvblwiOjEsXCJzc19wb3NcIjowMCxcIm1ham9yX3ZlcnNpb25cIjoyNDAsXCJnZW5lbmxpbmVfY29tbWVudF9jb21wb3Nlcl9mb3JfbmV3X3VzZXIiOmZhbHNlfWRnZXMiOltdfSwidmlld2VyX2FjdHNfYXNfcGVyc29uIjp7ImlkIjoiMTAwMDAwMDAwMDAwMDAwIiwibmFtZSI6IjAwMDAgQ2FsaTAwMHJpIn0sInN1Z2dlc3RlZF9EIiwic2Vjb25kYXJ5X3N1YnNjcmliZV9zdGF0dXMiOiJhbHNlLCJzZWVuX2NvdW50IjowfSwiY29udGVudF9jbGFzc2lmaWNhdGlvbl9jb250ZXh0Ijp7InByZWRpY3RlZF9mZWVkX3RvcGljcyI6W119LCJhdXRvX3Bpdm90X3VuaXQiOm51bGwsImhhc19mcnRwX2luZm8iOl93aXRoX3N0aWNrZXIiOnRydWUsImNhbl92aWV3ZXJfdWxsLCJwbGF5YWJsZV9kdXJhdGlvbl9pbl9tcyI6MCwiZmVlZGJ5IjpmYWxzZSwic2Vlbl9ieSI6eyJjb3VudCI6bnVsbH0sImNvbW1lbnRfYWdncmVnYXRlZF90b21ic3RvbmUiOm51bGwsIm1lc3NhZ2VoYXJlX2lkXCI6dWxsLCJpbnNpZ2h0cyI6bnVsbCwicG9zdF9pbnNpZ2h0cyI6bnVsbCwicGFnZXNfcG9zdF9sZXZlbF9pbnNpZ2h0c19xZSI6MCwicHJvbW90aW9uX2luZm8iOm51bGwsInBvc3RfcHJvbW90dHRhY2htZW50cyI6W09ORSIsInJhbmtpbmdfd2VpZ2h0IjplbXBvcmFyaWx5IHN0b3Agc2VlaW5nIHBvc3RzLiJ9LCJuZWdhdGl2ZV9mZWVkYmFja19hY3Rpb25fdHlwZSI6ImVyX21lc3NhZ2UiOnRydWUsImlzX21lc3NhZ2VfOm51bGx9LCJyZWNvbW1lbmRhdGlvbl9jb250ZXh0IjpudWxsLCJ2aWRlb19jaGFpbmluZ19jb250ZXh0Ijp7InNob3VsZF9wcmVmZXRjaCI6ZmFsc2UsImJsb2NrX2luaXRpYWxfY2hhaW5pbmdfZW5hYmxlZCI6ZmFsc2UsIjcyNzAwMDAwMDAwMDA6OGE3YjAwMDAwNjkwZGVkY2IxOTliMzA3MzAwMDIxNDQifSwic3RvcnlfYnVja2V0Ijp7Im5vZGVzIjpbeyJpZCI6IjAwMDA4MjgwNDMwNTE3OTciLCJpc19idWNrZXRfc2Vlbl9ieV92aWV3ZXIiOnRydWUsImlzX2J1Y2tldF9vd25lZF9ieV92aWV3ZXIiOmZhbHNlLCJjYW1lcmFfcG9zdF90eXBlIjoiU1RPUlkiLCJ0aHJlYWRzIjp7ImlzX2VtcHR5Ijp0cnVlfSwibGF0ZXN0X3RocmVhZF9jcmVhdGlvbl90aW1lIjp9XX19fSIsInRpdGxlIjpudWxsLCJzaG9ydF90ZXJtX2NhY2hlX3BlIjoiSFRNTF9PTkxZIiwiaW5hcHBfYnJvd3Nlcl9yYXBpZGZlZWRiYWNrX3N1cnZleXMiOltdLCJpc19uZXdfc3RvcnkiOmZhbHNlLCJzaG93X3NwYXRpYWxfcmVhY3Rpb25zIjpmYWxzZSwic2hvdWxkX3ByZWZldGNoX2luc3RhbnRfYXJ0aWNsZSI6YXkiOm51bGwsImlkZW50aXR5X2JhZGdlcyI6W10sInZpZGVvX2NyZWF0b3JfdG9wX2Zhbl9iYWRnZV9zdGF0dXMiOm51bGwsImlzX2Fub255bW91cyI6ZmFsc2UsImFza19hZG1pbl90b19wb3N0X2FjY2VwdF9kaWFsb2ciOm51bGwsImNhbl92aWV3ZXJfYXBwcm92ZV9wb3N0IjpmYWxzZSwiYXNrX2FkbWluX3RvX3Bvc3RfYXV0aG9yIjpudWxsLCJwb3N0X3N1YnNjcmlwdGlvbl9zdGF0dXNfaW5mbyI6bnVsbCwiY2FuX3Nob3dfdXBzZWxsX2hlYWRlciI6dHJ1ZSwiZnJpZW5kaGFyZUFjdGlvbkxpbmsiLCJwYWdlIjpudWxsLCJ1cmwiOm51bGwsImZlZWRfY3RhX3R5cGUiOiJVTktOT1dOIiwibGlua190eToiMTY3ODUyNDkzMjQzNDEwMiIsImtleSI6Mn19YXlvdXRfaGVpZ2h0IjowfSx7Il9fdHlwZW5hbWUiOiJhZ19leHBhbnNpb25fZWR1Y2F0LCJwYWdlc191bml2ZXJzYWxfZGlzdHJpYnV0aW9uX3BzZWxsX3FlIjpmYWxzZSwicnVlLCJpc19lbGlnaWJsZV9mb3JfZW50X3Byb3BlcnRpZXMiOlt7ImtleSI6InBob3Rvc2V0X3JlZmVyZW5jZXNjaG9vbCI6bnVsbCwiZW1wbG95ZXIiOm51bGxvbG9yIjpudWxsLCJ0byI6bnVsbCwic3VidGl0bGUiOm51bGwsImNyZWF0aW9uX3RpbWUiOjE1NzAwMDA3NTcsImJhY2tkYXRlZF90aW1lIjpudWxsLCJ1cmwiOiJodHRwczpcL1wvd3d3LmZhY2Vib29rLmNvbVwvMDAwMDAwMDAwMDAwMTYyXC9wb3N0c1wvMDAwNDgxMDAxNjAwMDAwXC8iLCJkaXNwbGF5X3RpbWVfYmxvY2tfaW5mbyI6bnVsbCwidGl0bGVGcm9tUmVuZGVyTG9jYXRpb24iOnVsbCwidGl0bGUiOm51bGx9XSwiYXR0YWNoZWRfYWN0aW9uX2xpbmtzIjpbXSwic2hhcmVhYmxlIjo6W10sInBhZ2UiOm51bGx9fV0sImFnZ3JlZ2F0ZWRfcmFuZ2VzIjpbXSwiaW1hZ2VfcmFuZ2VzIjpbXX0sIm1lc3NhZ2VfbWFya2Rvd25faHRtbCI6bnVsbCwibWVzc2FnZV9yaWNodGV4dCI6W10sIm1lc3NhZ2UiOmRpYWxlY3QiOiJlbl9YWCIsInRhcmdldF9kaWFsZWN0X25hbWUiOiIwbmdsaXNoIiwidHJhbnNsYXRpb25fdHlwZSI6Ik5PX1RSQU5TTEFUSU9OIiwidHJhc3RvcmllcyI6ZmFsc2UsImhhc19uaW1hdGVkX2RlZXBfbGlua3MiOmZhbHNlLCJwb2xsX3N0aWNrZXIiOmdhdGl2ZV9mZWVkYmFja19hY3Rpb25fdHlwZSI6InVsbCwic3ViYXR0YWNobWVudHMiOlt7InRpdGxlIjoiIiwic3VidGl0bGUiOm51bGwsInNuaXBwZXQiOm51bGwsInRpdGxlX3dpdGhfZW50aXRpZXMiOnsidGV4dCI6Il0sImlzX3ZpZGVvX2RlZXBfbGlua3MiOmZhbHNlLCJpc19jb250ZW50IjpudWxsc19hZ2VfcmVzdHJpY3RlZCI6ZmFsc2UsImlzX3BsYXlhYmxlIjpmYWxzZSwicGxheWFibGVfdXJsIjpudWxsLCJwbGF5YWJsZVVybEhkU3RyaW5nIjpudWxsLCJwcmVmZXJyZWRQbGF5YWJsZVVybFN0cmluZyI6bnVsbCwiYXRvbV9zaXplIjowLCJoZEF0b21TaXplIjowLCJiaXRyYXRlIjowLCJoZEJpdHJhdGUiOjAsInZpZGVvX2Z1bGxfc2l6ZSI6MCwiaXNfZGlzdHVyYmluZyI6LCJhc3NvY2lhdGVkX2FwcGxpY2F0aW9uIjpudWxsLCJkZWR1cGxpY2F0aW9uX2tleSI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMGQ5IiwiaW5zdGFncmFtX3VzZXIiOm51bGwsInVzZV9jYXJvdXNlbF9pbmZpbml0ZV9zY3JvbGwiOmZhbHNlLCJjOiJ7XCJxaWRcIjpcIjAwMDAwMDU4MjAxMDA5MzA1MjNcIixcIm1mX3N0b3J5X2tleVwiOlwiMDAwOTAwMDAwMDA3NjU4MTUyMjZcIixcInRvcF9sZXZlbF9wb3N0X2lkXCI6XCIwMDAwMDAzMTEwMDAwMDE5XCIsXCJjb250ZW50X293bmVyX2lkX25ld1wiOlwiMTAwMDAwMDA3MzAwMDAwXCIsXCI0Il0sImVuZF9jdXJzb3IiOm9weXJpZ2h0X2Jsb2NrX2luZm8iOm51bGwsImNvcHlyaWdodF9iYW5uZXJfaW5mbyI6eyJ0cmFuc2xhdGVkX2Jhbm5lcl9tZXNzYWdlIjpudWxsLCJkaXNwdXRlX3VyaSI6bnVsbCwiaWNvbiI6bnVsbCwibmF0aXZlX3RlbXBsYXRlX3ZpZXciOm51bGx9LCJnZXMiOlt7InByZXZpZXdfY2FsbF90b19hY3Rpb25fdGV4dCI6bnVsbCwicHJldmlld190ZXh0IjpudWxsLCJub2RlIjpudWxsfV19LCJmZWVkYmFja19jb250ZXh0Ijp7ImludGVyZXN0aW5nX3RvcF9sZXZlbF9jb21tZW50cyI6W10sInJlYWRfbGlrZWxpaG9vZCI6IkxPVyIsImluYXBwX2Jyb3dzZXJfcHJlZmV0Y2hfdnB2X2R1cmF0aW9uX3RocmVzaG9sZCI6LTEsImluYWxvY2siLCJ0YXJnZXRfZW50aXR5Ijp7Il9fdHlwZW5hbWUiOiIifSwic3VidGl0bGUiOnsidGV4dCI6Ik5PT1pFX0FDVE9SIiwibmVnYXRpdmVfZmVlZGJhY2tfYWN0aW9uLCJ0ZXh0X2RlbGlnaHRzX2FyZV9oaWRkZW4iOmZhbHNlLCJ0b3BpY3NfY29udGV4dCI6eyJ0b3BpY19mb2xsb3dlbmNvZGluZ3MiOltdLCJhdHRyaWJ1dGlvbl9hcHAiOm51bGwsImF0dHJpYnV0aW9uX2FwcF9tZXRhZGF0YSI6bnVsbCwiQ2hhbm5lbEVkZ2UiLCJzb3J0X2tleSI6IjE6MDAwMDAwMDAwMDE1NzAwMDAwMDM6MDQwMDEwMDAwMDg0MjAwMDAwMDQ6MDkwMDAwMDIwMzY4MDAwMDAwMDA6MDAwMDAwMDAwMDAwMDAwMDAwMDgiLCJkZWR1cGxpY2F0aW9uX2tleSI6IjAwMDc5MDEyMDA5MDAwMDAwMDI4IiwiaXNfaW5fbG93X2VuZ2FnZW1lbnRfYmxvY2siOmZhbHNlLCJidW1wX3JlYXNvbiI6IkJVTVBfb3VudCI6MCwiZWRnZXMiOltdfSwicHJvbW90aW9uc19jYXJvdXNlbF9uYXRpdmVfdGVtcGxhdGVfdmlldyI6bnVsbHNsYXRpb24iOm51bGx9LCJjYW5fdmlld2VyX2FwcGVuZF9waG90b3MiOmZhbHNlLCJjYW5fdmlld2VyX2VkaXQiOmZhbHNlLCJjYW5fdmlld2VyX2VkaXRfbWV0YXRhZ3MiOmZhbHNlLCJjYW5fdmlld2VyX2VkaXRfcG9zdF9tZWRpYSI6ZmFsc2UsImNhbl92aWV3ZXJfZWRpdF9wb3N0X3ByaXZhY3kiOmZhbHNlLCJjYW5fdmlld2VyX2VkaXRfbGlua19hdHRhY2htZW50IjpmYWxzZSwiY2FuX3ZpZXdlcl9kZWxldGUiOmZhbHNlLCJjYW5fdmlld2VyX3Jlc2hhcmVfdG9fc3RvcnkiOnRydWUsImNhbl92aWV3ZXJfcmVzaGFyZV90b19zdG9yeV9ub3ciOnVsbCwic3VmZml4IjpudWxsLCJpc19mb3hfc2hhcmFibGUiOmZhbHNlLCJhY3RvcnMiOlt7Il9fdHlwZW5hbWUiOiJkdWNhdGlvbl9pdGVtcyI6W10sInVuZGVybHlpbmdfYWRtaW5fY3JlYXRvciI6bnVsbCwiaWRlbnRpdHlfYmFkZ2VfY29tbWVudF90cn19LCJzYXZlX2luZm8iOnsidmlld2VyX3NhdmVfc3RhdGUiOiJOT1RfU0FWRUQiLCJzdG9yeV9zYXZlX3R5cGUiOiJQT1NUIiwic3Rvcnlfc2F2ZV9udXhfdHlwZSI6bnVsbCwic3Rvcnlfc2F2ZV9udXhfbWluX2NvbnN1bWVfZHVyYXRpb24iOm51bGwsInN0b3J5X3NhdmVfbnV4X21heF9jb25zdW1lX2R1cmF0aW9uIjpudWxsLCJzYXZlX2xpc3RzIjp7ImNvdW50IjowfSwic2F2YWJsZSI6eyJfX3R5cGVuYW1lIjoiMGhvdG8iLCJpZCI6IjAwMDUyMzIwMDAwMDAwMCIsInZpZXdlcl9zYXZlZF9zdGF0ZSI6Ik5PVF9TQVZFRCIsInNhdmFibGVfZGVmYXVsdF9jYXRlZ29yeSI6IiwiYXR0YWNoZWRfc3RvcnkiOm51bGwsImF0dGFjaGVkX3N0b3J5X3JlbmRlcnJjXCI6MjIsXCJwaG90b19pZFwiOlwiMDAwMDAwMDAwMDAwMDYyMFwiLFwic3RvcnlfbG9jYXRpb25cIjo1LFwic3RvcnlfYXR0YWNobWVudF9zdHlsZVwiOlwibl9mZWVkIjpmYWxzZSwib2JqZWN0aW9uYWJsZV9jb250ZW50X2luZm8iOm51bGxvcHlyaWdodF9hdHRyaWJ1dGlvbl9uYXRpdmVfdGVtcGxhdGVfdmlldyI6bnVsbCwiY2FtZXJhX3Bvc3RfaW5mbyI6eyJzaGFyZWFibGVfaWQiOnVsbH1dfSwiaXNfd29ya191c2VyIjpmYWxzZSwid29ya19mb3JlaWduX2VudGl0eV9pbmZvIjpudWxsLCJ3b3JrX2luZm8iOm51bGwsInByb2ZpbGVfdmlld2VyX3Jlc2hhcmVfdG9fc3Rvcnlfbm93IjpmYWxzZSwic3Vic3Rvcmllc19ncm91cGluZ19yZWFzb25zIjpbXSwidmlhIjpudWxsLCJ3aXRoX3RhZ3MiOnsibm9kZXMiOltdfSwiYXBwbGljYXRpb24iOm51bGwsInN1YnN0b3J5X2NvdW50IjowLCJpbXBsaWNpdF9wbGFjZSI6bnVsbCwiZXhwbGljaXRfcGxhY2UiOm51bGwsInBhZ2VfcmVjX2luZm8iOm51bGwsInNwb25zb3JlZF9kYXRhIjpudWxsLCJpc19hdXRvbWF0aWNhbGx5X3RyYW5zbGF0ZWQiOmZhbHNlLCJzcG9uc29yX3JlbGF0aW9uc2hpcCI6MCwiYWN0aW9uX2xpbmtzIjpbeyJfX3R5cGVuYW1lIjoiaWRlb19hdXRvcGxheVwiLFwidmlld190aW1lXCI6MTU3MDAwMzc4MCxcImZpbHRlclwiOlwiaF9ub3JcIixcImFjdHJzXCI6XCIxMHJpZ2dlciI6bnVsbCwiMzEifSwidGFyZ2V0X2VudGl0eV90eXBlIjoiUEVPUExFIiwiZmVlZGJhY2tfdGFncyI6W10sInVybCI6bnVsbH19LHsibm9kZSJhd2xlZF9zdGF0aWNfcmVzb3VyY2VzIjpbXSwic3R5bGVfaW5mb3MiOltzdG9yeV9wcm9tb3Rpb25zX2luZm8iOnsicHJvbW90aW9ucyI6eyJlc2hhcmVfY29tcG9zZXJfY29uZmlybV9kaWFsb2dfY29uZmlnIjpudWxsLCIsIm11bHRpYWRnZSI6bnVsbCwic3Vic2NyaWJlX3N0YXR1cyI6IjQwLFwiZ2VuZXJhdG9yX3Jvd19pZFwiOjAxMCxcImJhY2tlbmRfcG9zaXRpb25cIjowLFwic29ydF9rZXlcIjoxMDAwMDAwMDAwMDAwfSIsImRpc2FsbG93X2ZpcnN0X3Bvc2l0aW9uIjpmYWxzZSwic3BvbnNvcmVkX2F1Y3Rpb25fZGlzdGFuY2UiOjAsInNwb25zb3JlZF9mb3J3YXJkX2Rpc3RhbmNlIjpudWxsLCJzdG9yeV90eXBlX2JhY2tlbmQiOjA2MywiY2F0ZWdvcnkiOiJPUkdBTklDIiwic3RvcnlfcmFua2luZ190aW1lIjoxNTA5OTA0MDMyLCJhbGxvY2F0aW9uX2dhcF9oaW50IjpudWxsLCJ0b3BfYWRfcG9zaXRpb24iOm51bGwsImZlZWRfcHJvZHVjdF9kYXRhIjp7ImlzX2luc3RhbnRfZmVlZF9jYWNoZWRfc3RvcnkiOmZhbHNlfSwiZmVlZF9iYWNrZW5kX2RhdGEiOnsicWlkIjoiNjc0ImVsaWdpYmxlX2Zvcl9lZHVjYXRpb24iOmZhbHNlLCJzaG93X2FjdGl2ZV9lZHVjYXRpb24iOmV5Ijo4fV0sImltcG9ydGFudF9yZWFjdG9ycyI6eyJhbWVzQXBwU3RvcnlBdHRhY2htZW50U3R5bGVJbmZvIn1dLCJyaWVuZHNlZmVyZW5jZWRfc3RpY2tlciI6bnVsbCwidGV4dF9mb3JtYXRfbWV0YWRhdGEiOm51bGwsImFsYnVtIjpudWxsLCJ2ZXJpZmllZF92b2ljZV9jb250ZXh0IjpudWxsLCJicmFuZGVkX2NvbnRlbnRfaW50ZWdyaXR5X2NvbnRleHRfInRpdGxlIjpudWxsLCJ2YWx1ZSI6eyJ0ZXh0IjoiYXNfY29tcHJlaGVuc2l2ZV90aXRsZSI6ZmFsc2UsImVkbmdfdG9waWN9LCJyYXBpZF9yZXBvcnRpbmdfcHJvbXB0Ijp7ImVuYWJsZWQiOmZhbHNlfSwiZnJ4X2NvbnRlbnRfb3ZlcmxheV9wcm9tcHQiOm51bGwsIm11bHRpbGluZ3VhbF9hdXRob3JfZGlhbGVjdHMiOltdLCJhdXRob3JfdHJhbnNsYXRpb25zIjpbXSwidHJhbnNsYXRhYmlsaXR5X2Zvcl92aWV3ZXIiOnsic291cmNlX2RpYWxlY3QiOiJlbGV0ZSI6ZmFsc2UsImNhbl92aWV3ZXJfYWdlIiwiaWQiOiIwMDAwMDAwMDAwOTA5NDUiLCJuYW1lIjoiMDAwMDAwMDBraW5nLiIsInByb2ZpbGVfcGljdHVyZSI6eyJ1cmkiOiJodHRwczpcL1wvc2NvbnRlbnQwMGJlMS0xLnh4LmZiY2RuLm5ldFwvdlwvdDEuMC0xXC9jcDBcL2UxNVwvcTY1XC9wMDR4NzRcLzAwOTc3NTAwXzY2MDAwMDAwMDAwMDAwMF8wMDAwMDAwMjAwMTEwMDAwMF9uLmpwZz9fbmNfY2F0PTFIRVZST05fRkVFREJBQ0tfRU5UUllQT0lOVCIsInRhcmdldF9lbnRpdHkiOm51bGwsInRhcmdldF9lbnRpdHlfdHlwZSI6bnVsbCwiZmVlZGJhY2tfdGFncyI6W10sInVybCI6bnVsbH19c3R5bGUiOiJERUZBVUxUIiwiYWxsX3N1YiJkZWJ1Z19pbmZvIjpudWxsLCJob3RvIiwiZ2FtZXNfYXBwIiwiZmFsbGJhY2siXSwiaGFyZUF0dGFjaG1lbnRXaXRoSW1hZ2VGaWVsZHMiOltdLCJmZWVkYmFjayI6eyJpZCI6IjAwMDAwMDAwMDJzNk0wMDBOekkyTWprek4wUTAwVFV3IiwiYWNjZXB0ZWRfYW5zd2VyIjpudWxsLCJjYW5fcGFnZV92aWV3ZXJfaW52aXRlX3Bvc3RfbGlrZXJzIjpvbW1lbnRfd2l0aF9jMi0xLmZuYSZvaD0wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDk0MiZvZT01RTIwMDY4RSIsIndpZHRoIjowNDAsImhlaWdodCI6MDQwfSwidG9yaWVzIjp7InJlbWFpbmluZ19jb3VudCI6MCwibm9kZXMiU19TVUJTQ1JJQkVEdWxsfSwicGFnZV9leGNsdXNpdmVfcG9zdF9pbmZvIjpudWxsLCJuZXdzZmVlZF91c2VyX3RfaGlzdG9yeSI6eyJjb3VudCI6MH0sImlubGluZV9hY3Rpdml0aWVzIjp7Im5vZGVzIjpbXX0sImRpc3BsYXlfZXhwbGFuYXRpb24iOm51bGwsInN0b3J5X2F0dHJpYnV0aW9uIjpudWxsLCJzdG9yeV9oZWFkZXIiOm51bGwsImNyaXNpc19saXN0aW5nIjpudWxsLCJibG9vZF9yZXF1ZXN0IjpudWxsLCJhY3Rpb25zIjpbXSwic3VwcGxlbWVudGFsX3NvY2lhbF9zdG9yeSI6bnVsbCwidmlld2VyX2VkaXRfcG9zdF9mZWF0dXJlX2NhcGFiaWxpdGllcyI6WywiYW5kcm9pZF91cmxzIjpbXSwiYXBwbGljYXRpb24iOm51bGwsInByb2ZpbGVfcGljdHVyZSI6SU5LIiwiaXNfc3BoZXJpY2FsIjpmYWxzZX19LCJsZWdhY3lfYXBpX3N0b3J5X2lkIjpdLCJwcml2YWN5X3Njb3BlIjp7ImxhYmVsIjoiMHVibGljIiwidHlwZSI6ImV2ZXJ5b25lIiwiaWNvbiI6eyJ1cmkiOiJodHRwczpcL1wvc3RhdGljLnh4LmZiY2RuLm5ldFwvcnNyYy5waHBcL3YzXC95MFwvclwvMC1zb0xNSWJKYUoucG5nIiwibmFtZSI6ImV2ZXJ5b25lIiwid2lkdGgiOjEwLCJoZWlnaHQiOjAxfSwiY2FuX3ZpZXdlcl9lZGl0IjpmYWxzZSwiZWR1Y2F0aW9uX2luZm8iOnsicmVzaGFyZV9lZHVjYXRpb25faW5mbyI6LCJkaW1lbnNpb25sZXNzX2NhY2hlX2tleSI6IiwiY2NvbW1lbnQiOm9kZSI6eyJfX3R5cGVuYW1lIjoiU3RvcnkiLCJpZCI6IlV6cGZTVEV3TURBd3VsbCwiY292ZXJfcGhvdG8iOm51bGwsInNvY2lhbF9jb250ZXh0IjpudWxsLCJtZWRpYWFjdGlvbiI6bnVsbG5pbWF0ZWRfaW1hZ2VibGVfd2FybmluZ19tIiwicmFuZ2VzIjpbeyJvZmZzZXQiOjAsImxlbmd0aCI6MTAsImVudGl0eSI6LCJyYW5nZXMiOltdLCJkZWxpZ2h0X3JhbmdlcyI6W119LCJmZXRjaF90dG9rZW4ifSx7ImtleSI6N30seyJrZXkiOjh9XUVHVUxBUl9GT0xMT1ciLCJ1cmwiOiJodHRwczpcL1wvbS5mYWNlYm9vay5jb21cL2ljb25fbmFtZSI6InVsbH1dLCJmZWVkYmFjayI6fSwidG9wX2xldmVsX2NvbW1lbnRzIjp7ImNvdW50IjowLCJ0b3RhbF9jb3VudCI6MH0sImxpa2VycyI6eyJjb3VudCI6MH0sInJlc2hhcmVzIjp7ImNvdW50IjowfSwiZGVmYXVsdF9jb21tZW50X29yZGVyaW5nIjoidG9wbGV2ZWwiLCJzaG93X3RhcF90b19zZWVfYmxpbmdfYmFyIjpmYWxzZSwiY2FuX3Nob3dfc2Vlbl9zIjp7Im51bV9hY3Rpb25zX2Fib3ZlX2ZvbGQiOm51bGwsIm51bV9hY3Rpb25zX2ZvbGRlZCI6bnVsbCwiZWRnZXMiOlt7Im5vZGUiOnsiLCJzb3VyY2VfZGlhbGVjdF9uYW1lIjoifSwidmlld2VyX2N1cnJlbnRfYWN0b3IiOnsiX190eXBlbmFtZSI6IlVzZXIiLCJpZCI6IjEwMDAwMDAwMDAwMDAwMCIsIm5hbWUiOiIwbzBnIDAwIn0sImN1c3RvbV9zdGlja2VyX3BhY2siOm51bGwsImN1c3RvbV9zdGlja2VyX3BhY2tfbnV4X2NvbnRlbnQiOm50eWxlX2xpc3QiOlsiaG93X29iamVjdGlvbmVnYWN5X2FwaV9wb3N0X2lkIjoiMDAwMDkwMzAwMDA1MjM4MiIsInZpZXdlcl9hY3RzX2FzX3BhZ2UiOm51bGwsImNvbW1lbnRzX21pcnJvcmluZ19kb21haW4iOm51bGwsIm93bmluZ19wcm9maWxlIjp7Il9fdHlwZW5hbWUiOiJ1YnNjcmliZSI6dHJ1ZSwiY29tbXVuaXR5X2NvbnZlcnNhdGlvbnNfY29udGV4dCI6eyJhbGxvd19wcml2YXRlX2xvdW5nZV9jb252ZXJzYXRpb25zIjpmYWxzZSwicHJlZmVycmVkX3ByaXZhY3lfdmFsdWUiOiJERUZBVUxUX1BSSVZBQ1kifSwiZG9lc192aWV3ZXJfbGlrZSI6Im5vZGUiOnsiaWQiOiIxNjM1ODU1NDg2NjY2OTk5Iiwia2V5IjoxfX1dfSwidmlld2VyX2ZlZWRiYWNrX3JlYWN0aW9uX2tleSI6MCwidWxsLCJjYW5fc2VlX3ZvaWNlX3N3aXRjaGVyIjpmYWxzZSwiY2FuX119LCJpY29uX2ltYWdlIjp7Im5hbWUiOiI6bnVsbCwiaW1hZ2UiOnsidXJpIjoiaHR0cHM6XC9cL3Njb250ZW50LmYwMGUxLTEuZm5hLmZiY2RuLm5ldFwvdlwvdDEuMC11cHBvcnRlZF9yZWFjdGlvbjAiOlt7ImtleSI6MX0seyJrZXkiOjJ9LHsia2V5Ijo0fSx7ImtleSI6ZXNjcmlwdGlvbiI6aXRsZSI6eyJ0ZXh0Ijoic2VyIiwiaWQiOiIxMDAwMCwicmVhY3RvcnMiOnsiY291bnQiOjB9LCJ0b3BfcmVhY3Rpb25zIjp7ImVkZ2VzIjpbeyJyZWFjdHRhcnRfY3Vyc29yIjphbHNlLCJpc192aWV3ZXJfc3Vic2NyaWJlZCI6ZmFsc2UsInVsbCwidXJsIjoiaHR0cHM6XC9cL20uZmFjZWJvb2suY29tXC8mX25jX2FkPXotbSZfbmNfY2lkPTAmX25jX3pvcj05Jl9uY19odD1zY29udGVudC5mdWxsLCIiTmV3c0ZlZWRRdWVyeURlcHRoMyI6eyJkYXRhIjp7InZpZXdlciI6eyJuZXdzX2ZlZWQiOnsiZWRnZXMiOltvbl9jb3VudCI6YWdlX2luZm8iOnsiaWRlbyI6dHJ1ZSwiY2FuX3ZpZXdlcl86bnVsbCwiX25jX29jPUFRfX19LCJleHRlbnNpb25zIjp7InNlcnZlcl9tZXRhZGF0YSI6eyJyZXF1ZXN0X3N0YXJ0X3RpbWVfbXMiOjE1NzAwMDAwNDkwNjYsInRpbWVfYXRfZmx1c2hfbXMiOjE1NzAwMDAwNDAwODF9LCJpc19maW5hbCI6dHJ1ZX19"  # noqa: E501


class Filter:
    def __init__(self):
        # only apply to traffic, which fullfills the following conditions, as the ZSTD compression dict only applies to this
        # - request URL 'graph.facebook.com/graphql'
        # - response header 'content-encoding: x-fb-dz' exists (indicates usage ZSTD compression)
        # - response header 'x-fb-dz-dict: 1' exists (indicates that the ZSTD dict #1 was used to create the response)
        #
        # Warning: There is no filter criteria which enforce traffic for a specific client version, while the dict in use was
        #          extracted from Faceboo Android App v342.0.0.37.119. To train dictionaries for ZSTD compression is an ongoing
        #          process, which means facebook will very likely ship newer versions of the dictionary with newer clients
        self.filter: flowfilter.TFilter = flowfilter.parse('~u graph.facebook.com/graphql & ~hs "x-fb-dz-dict:\\\\s*1" & ~hs "content-encoding:\\\\s*x-fb-dz"')
        d_dict=zstandard.ZstdCompressionDict(data=b64decode(FB_ZSTD_DICT1))
        self.decompressor = zstandard.ZstdDecompressor(d_dict)


    def load(self, loader):
        pass

    def response(self, flow: http.HTTPFlow) -> None:
        if flowfilter.match(self.filter, flow):
            ctx.log.info("Flow matches filter:")
            # decompress the body
            if flow.response is not None and flow.response.raw_content is not None:
                compressed = flow.response.raw_content
                try:
                    decompressed = self.decompressor.decompress(compressed)
                    # replace content
                    flow.response.content = decompressed
                    # remove 'content-encoding', x-fb-dz' and 'x-fb-dz-dict' headers
                    del flow.response.headers[b"content-encoding"]
                    del flow.response.headers[b"x-fb-dz-dict"]
                    
                    ctx.log.info(decompressed)
                except:
                    pass  # if it fails, it fails
                



addons = [Filter()]
