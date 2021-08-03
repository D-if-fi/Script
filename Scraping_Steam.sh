#!/bin/bash
while read line
do
echo $line
echo "游戏名称:"
curl -s -L -H 'Accept-Language:zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6' --cookie "wants_mature_content=1; steamCountry=CN|bd0b62ec8cbaa915509617d99bd9c765; browserid=2416726443827414633; sessionid=ab82781cb3f0fc58c30a9b45; timezoneOffset=28800,0; _ga=GA1.2.812482494.1625302619; _gid=GA1.2.1764750884.1625302619; birthtime=91987201; lastagecheckage=1-0-1973; _gat_app=1; recentapps={"1091500":1625302655}"  https://store.steampowered.com/app/$line |grep '名称:' |awk -F '</b>' '{print $2}' |sed 's#<br>##'
echo "发售日期:"
curl -s -L -H 'Accept-Language:zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6' --cookie "wants_mature_content=1; steamCountry=CN|bd0b62ec8cbaa915509617d99bd9c765; browserid=2416726443827414633; sessionid=ab82781cb3f0fc58c30a9b45; timezoneOffset=28800,0; _ga=GA1.2.812482494.1625302619; _gid=GA1.2.1764750884.1625302619; birthtime=91987201; lastagecheckage=1-0-1973; _gat_app=1; recentapps={"1091500":1625302655}"  https://store.steampowered.com/app/$line  |grep 发行日期 |awk -F "</b>" '{print $2}' |sed 's#<br>##' | xargs
echo "游戏信息:"
curl -s -L -H 'Accept-Language:zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6' --cookie "wants_mature_content=1; steamCountry=CN|bd0b62ec8cbaa915509617d99bd9c765; browserid=2416726443827414633; sessionid=ab82781cb3f0fc58c30a9b45; timezoneOffset=28800,0; _ga=GA1.2.812482494.1625302619; _gid=GA1.2.1764750884.1625302619; birthtime=91987201; lastagecheckage=1-0-1973; _gat_app=1; recentapps={"1091500":1625302655}"  https://store.steampowered.com/app/$line |grep -C5 '关于这款游戏' |xargs  |sed 's#<br />##g' |sed 's#<h2>##g' |sed 's#</h2>##g'
echo "操作系统:"
curl -s -L -H 'Accept-Language:zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6' --cookie "wants_mature_content=1; steamCountry=CN|bd0b62ec8cbaa915509617d99bd9c765; browserid=2416726443827414633; sessionid=ab82781cb3f0fc58c30a9b45; timezoneOffset=28800,0; _ga=GA1.2.812482494.1625302619; _gid=GA1.2.1764750884.1625302619; birthtime=91987201; lastagecheckage=1-0-1973; _gat_app=1; recentapps={"1091500":1625302655}"  https://store.steampowered.com/app/$line |grep "最低配置:" |grep "操作系统:" |awk -F '</strong>' '{print $3}' |awk -F '<br>' '{print $1}'
echo "------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
done<steam_id.txt