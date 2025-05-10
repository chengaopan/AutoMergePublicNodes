# NoMoreWalls

[![Fetch Status](https://github.com/chengaopan/AutoMergePublicNodes/actions/workflows/fetch.yml/badge.svg)](https://github.com/chengaopan/AutoMergePublicNodes/actions/workflows/fetch.yml) [![Stars](https://img.shields.io/github/stars/chengaopan/AutoMergePublicNodes?style=flat)](https://github.com/chengaopan/AutoMergePublicNodes/stargazers) [![Watchers](https://img.shields.io/github/watchers/chengaopan/AutoMergePublicNodes?style=flat)](https://github.com/chengaopan/AutoMergePublicNodes/watchers) [![Forks](https://img.shields.io/github/forks/chengaopan/AutoMergePublicNodes?style=flat)](https://github.com/chengaopan/AutoMergePublicNodes/forks) [![Repo size](https://img.shields.io/github/repo-size/chengaopan/AutoMergePublicNodes)](https://github.com/chengaopan/AutoMergePublicNodes/commits) ![Vistors](https://visitor-badge.laobi.icu/badge?page_id=peasoft.NoMoreWalls) [![996.icu](https://img.shields.io/badge/link-996.icu-red.svg)](https://996.icu) [![LICENSE](https://img.shields.io/badge/license-Anti%20996-blue.svg)](https://github.com/chengaopan/AutoMergePublicNodes/blob/master/LICENSE.md) [![暮光计划](https://img.shields.io/badge/link-暮光计划--向戒网瘾学校宣战-red.svg)](https://proj3ctaurora.tilda.ws/)

自动抓取合并互联网上的公开节点。
🚀 免费节点,🚀免费节点订阅,🚀v2ray免费节点,ssr免费节点订阅,clash免费节点订阅,免费梯子,免费翻墙,免费科学上网,免费ss/v2ray/trojan/clash节点,谷歌商店,翻墙梯子

## 公告
* 本项目fork [NoMoreWalls](https://github.com/peasoft/NoMoreWalls) 请优先为该项目 点亮☆
* 为防止失联，[peasoft](https://github.com/peasoft)建立了镜像：<https://peasoft.github.io/NWalls.html>

**本项目提供的 Clash 订阅包含我们精心设计的分流规则，Google Play 软件秒下，自动识别被墙域名，只需将 `🐟 漏网之鱼` 维持在 `DIRECT` 即可！**

由于江苏电信、移动经常屏蔽未备案域名，本项目能自动识别屏蔽并分流，如果你仍然遇到跳转反诈中心，请将 `❓ 疑似国内` 切换为 `🚀 选择代理`。

本项目拒绝为**流氓资本家**提供任何服务！特别的，项目的许可证**严格禁止**实行 996 工作制的公司使用本项目！

由于 [BootCDN/Staticfile 已被病毒公司收购](https://www.52pojie.cn/thread-1944970-1-1.html)，我们拦截了这些网站。

如果您访问部分网站时遇到问题，可以将 `病毒网站` 分类切换为 `DIRECT`，但是您需要**自行承担一切安全风险，包括但不限于广告骚扰，账号被盗，设备中毒**等，请三思而后行！！！

为防止失联，我们建立了镜像：<https://peasoft.github.io/NWalls.html>

我们新增了 `snippets` 文件夹来存放从 `list.meta.yml` 中拆分出的配置片段，用于将本项目提供的一些配置整合到你自己的配置中。

此项目现已添加“反 996 许可证”，请各位使用者**不要违法违规要求别人加班，自觉遵守《中华人民共和国劳动法》及其它法律法规**！

### 为什么 *不要* 使用付费节点？

1. 付费节点存在付完费厂商立即跑路的**诈骗风险**，且一旦被骗钱款**无法追回**！
2. 付费节点需要注册账号并付费，厂商可以借此收集你的**个人信息**然后倒卖！付费节点管理程序可能**存在漏洞**，■■黑客也可能把你的个人信息提交给■■。
3. 付费节点数量少，一旦封禁死亡率就是 100%。与其花**几倍的钱**购买多个机场备用，不如使用本项目收集的**全网各处**公开的节点，总数是付费订阅的 10 倍，**总有不少节点存活**！
4. 现在免费节点的质量并不差，Hysteria 节点**秒开 4K 不是梦**！![秒开 4K](https://github.com/user-attachments/assets/ea73db01-e7bf-4e31-a06f-13c91e9ee87c)


## 使用方法

注意：加速链接可能会失效，如果无法更新订阅，请把所有链接从上到下每个试一遍！你可以在电脑浏览器上安装油猴脚本 [Github 增强 - 高速下载](https://greasyfork.org/zh-CN/scripts/412245)，在目录浏览点开 `list.txt`，然后在 `Raw` 按钮边上找到最新的加速链接。

添加 Base64 订阅：
- [原始链接](https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt)
- [GhProxy.cn](https://ghproxy.cn/https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt)
- 此处不公开部分私有镜像站

以下链接可能不是最新，但绝对不会被封：
- [JsDelivr 默认 (当前 Fastly)](https://cdn.jsdelivr.net/gh/chengaopan/AutoMergePublicNodes@master/list.txt)
- [JsDelivr Fastly CDN](https://fastly.jsdelivr.net/gh/chengaopan/AutoMergePublicNodes@master/list.txt)
- [JsDelivr Cloudflare CDN](https://testingcf.jsdelivr.net/gh/chengaopan/AutoMergePublicNodes@master/list.txt)
- [JsDelivr GCore CDN](https://gcore.jsdelivr.net/gh/chengaopan/AutoMergePublicNodes@master/list.txt)

或添加 Clash Meta 订阅：（如果使用的是原版 Clash，请将链接最后的 `.meta.yml` 替换成 `.yml`。如果 Meta 提示解析错误，请**更新 Meta 至最新版本**！）
- [原始链接](https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.meta.yml)
- [GhProxy.cn](https://ghproxy.cn/https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.meta.yml)
- 此处不公开部分私有镜像站

以下链接可能不是最新，但绝对不会被封：
- [JsDelivr 默认 (当前 Fastly)](https://cdn.jsdelivr.net/gh/chengaopan/AutoMergePublicNodes@master/list.meta.yml)
- [JsDelivr Fastly CDN](https://fastly.jsdelivr.net/gh/chengaopan/AutoMergePublicNodes@master/list.meta.yml)
- [JsDelivr Cloudflare CDN](https://testingcf.jsdelivr.net/gh/chengaopan/AutoMergePublicNodes@master/list.meta.yml)
- [JsDelivr GCore CDN](https://gcore.jsdelivr.net/gh/chengaopan/AutoMergePublicNodes@master/list.meta.yml)

或添加 Sing-Box 订阅：（第三方提供转换，不支持本项目的节点选择和分流规则）
- [转换链接（第三方）](https://subapi.fxxk.dedyn.io/sub?target=singbox&url=https%3A%2F%2Fraw.githubusercontent.com%2Fpeasoft%2FNoMoreWalls%2Fmaster%2Fsnippets%2Fnodes.meta.yml&insert=false&config=https%3A%2F%2Fraw.githubusercontent.com%2FACL4SSR%2FACL4SSR%2Fmaster%2FClash%2Fconfig%2FACL4SSR_Online_Full_NoAuto.ini&tls13=true&emoji=true&list=false&xudp=true&udp=true&tfo=false&expand=true&scv=false&fdn=false&singbox.ipv6=1)

## 免责声明

订阅节点仅作学习交流使用，用于查找资料，学习知识，不做任何违法行为。所有资源均来自互联网，仅供大家交流学习使用，出现违法问题概不负责。**做出违法行为需要承担法律责任，侥幸逃脱是不可能的**！~~为阻止违法行为，本项目随时可以停止运行~~ 本项目可以采取各种技术手段来尽力阻止违法行为。

## 关于 Fork 和在线部署

不是说不能 Fork，但是请记得定时点击仓库中的 Sync fork 来同步更新主程序。这个项目是有时效性的，老版本基本都不能用了。

## 本地部署

1. 克隆本仓库，由于本仓库的完整 Commit 历史极大，请务必指定 `--depth=1`：
    ```bash
    git clone https://github.com/chengaopan/AutoMergePublicNodes.git --depth=1
    ```
2. 安装依赖库（此步骤需要 Git）
    ```bash
    pip install -r requirements.txt
    ```
3. 如果你所在地区没有墙或你在使用 Tun 模式或透明代理，请跳到第 9 步
4. 如果你已有代理，请跳到第 8 步。
5. 创建空白文件 `local_proxy.conf`
6. 运行 `fetch.py`
7. 将生成的订阅导入代理工具并正确配置好代理
8. 在 `local_proxy.conf` 中按如下格式填入你的代理工具的 http(s) 地址，如：
   ```plain
   http://127.0.0.1:7890/
   ```
9. 运行 `fetch.py`
10. 你已获得完整订阅

如果本地仓库长期未更新，请删除仓库并重新克隆来同步最新更改，不要使用 `git pull`。

## 一些题外话

各位看一看：

- **[油罐车事件是最好的照妖镜，上赶着带节奏都是谁请大家记下来。](https://www.bilibili.com/video/BV1p1421b7Ki)私有化愈发严重影响的是所有中国人的切身利益，必须用公有平衡私有我们才有发展的前途。**

上方事件的严重性已经远超下面的事情了。

- **[【独家恢复】我们的教育弄虚作假，到底是为了什么](https://peasoft.github.io/2023/08/26/cnedu.html)：如此视频，为何惨遭删除？我们恢复了这段视频，只为让更多人可以看清现实。**
- **[最流氓的软件可以流氓到什么程度？](https://www.zhihu.com/question/29129310)我翻开其他网页一查，歪歪斜斜的每页上都写着“危险网页”几个字。我横竖睡不着，仔细看了半夜，才从字缝里看出字来，满本都写着两个字是“霸权”！**
- **[百度？百毒！](https://user.guancha.cn/main/content?id=100552)魏则西去世3周年：害死他的百度广告和莆田系医院**
- **[《满江红》的行为艺术](https://www.bilibili.com/video/BV11v4y1t7Gw/)：秦桧竟是我自己？**
- **[「 深蓝洞察 」2022 年度最“不可赦”漏洞](https://mp.weixin.qq.com/s/P_EYQxOEupqdU0BJMRqWsw)：知名互联网厂商(TMD并夕夕)持续挖掘新的安卓 OEM 相关漏洞，在其公开发布的 App 中实现对目前市场主流手机系统的漏洞攻击**（[具体分析](https://mp.weixin.qq.com/s/kiLvnJSDZpYRHI_XiUx9gg)）~~现已被工信部提名~~
- **[暑假学校敢补课？举报！](https://www.bilibili.com/video/BV1Vk4y1K79B)**
- **[逃离戒网瘾学校？我们找到办法了](https://www.bilibili.com/video/BV1Mg4y1A7bE)：希望你永远用不到。**
- **[一学校扔掉学生百余份外卖](https://www.bilibili.com/video/BV1a14y1S7n6)：涉嫌违法！**
- **[没收违法所得的合法性与合理性基础欠缺——简评承德程序员事件](https://www.dehenglaw.com/CN/tansuocontent/0008/029562/7.aspx?MID=0902)**
- **[【BootCDN/Staticfile投毒分析】供应链投毒后，我们的选择还剩下哪些？](https://www.52pojie.cn/thread-1944970-1-1.html)**
- 未完待续……

## Star History

<a href="https://star-history.com/#chengaopan/AutoMergePublicNodes">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=chengaopan/AutoMergePublicNodes&theme=dark" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=chengaopan/AutoMergePublicNodes" />
    <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=chengaopan/AutoMergePublicNodes" />
  </picture>
</a>
