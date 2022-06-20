# SpringVulScan

## SpringVulScan--burpsuite插件
### 各位友友们，目前还正在测试。预计月底上传上。
## 写在前边

这是我开发的第一款burpsuite插件，本着的目标是为了更好更方便的去检测一些可能存在Spring漏洞的地方。第一次开发它也是遇到了许许多多的问题和困难，从收集互联网关于burpsuite插件开发资料（API，说明文档），到现在基本功能已经能够实现，前后经历了半个月左右的时间（中间也是掺杂了一些其他的琐事）。不过好在现在已将完成了它！！想着自己有时间搞一个burpsuite插件开发的思路（API的使用），内容文档我也会放到GitHub上，以后有时间继续维护它！！下边对其功能和使用方法进行介绍。

## 功能介绍

**界面**

![img](https://cdn.nlark.com/yuque/0/2022/png/21739648/1655642522435-9442e040-9680-4a09-ae0b-c691e02ae3fb.png)

长相也就一般般，GUI也是搞了一阵子。

| 功能点   | 介绍                                                         |
| -------- | ------------------------------------------------------------ |
| 基础设置 | 无话可说                                                     |
| 检测方式 | 回显和回连，无话可说。一般情况下基本上全开就行了。           |
| 扫描类型 | 同一站点仅检测一次：默认开启，开启后，同一个站点只进行一次检测，不会因为url的变化而再次检测。过滤检测Spring框架：默认关闭，开启后，自动根据Spring的特性，"whitelabel error page"，进行过滤性检测。而不会对其他流量进行再一次扫描。 |
| 编号检测 | 可指定漏洞类型进行检测。                                     |
| 回连平台 | 目前仅仅支持burpcollaborator，DnsLog.cn。其他平台功能暂未完善。若目标没做流量限制，建议使用burpcollaborator，扫描速度快且结果准确。 |

​	**文件目录**

![img](https://cdn.nlark.com/yuque/0/2022/png/21739648/1655643243635-61ed581d-c43e-4b68-8ea8-e78f9e583987.png)

```bash
conifg
------apiRoute.txt		泄露路由检测，可自定义。
------config.yml			CVE漏洞检测payload，部分payload不建议自定义。
SpringVulScan-1.0.jar
```

​	**检测效果**

![img](https://cdn.nlark.com/yuque/0/2022/png/21739648/1655643585846-c399a4fb-ebf4-4b8d-a37b-6a637ed5c179.png)

这个面板不是很方便，然后就添加到了仪表盘。所以直接在仪表盘查看是否存在漏洞即可。

![img](https://cdn.nlark.com/yuque/0/2022/png/21739648/1655643921940-656462a1-2ab5-496c-bf2d-c527a64df969.png)

像*CVE-2022-22965*这种可直接进行利用的，而且便于检测，所以直接报出高危红色即可，像api泄露这种检测起来不是很容易的就在Low和Medium面板。当然Medium面板的概率大于Low面板，相较于更准确些。

![img](https://cdn.nlark.com/yuque/0/2022/png/21739648/1655643953534-425a80ad-7c4a-43a6-82fe-61000f4f4f74.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/21739648/1655643972721-000088b8-f73a-4c25-8c2e-28a3c4097357.png)

## 总结

基本的注意点和用法就这么些，初次开发第一个工具，肯定存在一些未知的问题，还请直接提交issue。

##  参考

https://portswigger.net/burp/extender/api/burp/package-summary.html

https://xz.aliyun.com/t/7065

以及一些其他的开源插件
