这是参照官方微信文档整理的登录总结

更详细的获取用户数据等流程可以看https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
# 第一步：请求CODE
我们将用应用appid和一些静态值换取code码
## 跳转至微信扫码页面
```
https://open.weixin.qq.com/connect/qrconnect?
    appid=wxbdc5610cc59c1631&
    redirect_uri=https%3A%2F%2Fpassport.yhd.com%2Fwechat%2Fcallback.do&
    response_type=code&
    scope=snsapi_login&
    state=a4df54aa7eecaad018bbda169bd6bc12
    #wechat_redirect
```
## 用户扫码后自动调至确认页面
```
https://passport.yhd.com/wechat/callback.do?
    code=CODE&
    state=3d6be0a4035d839573b04816624a415e
```
# 第二步：通过code获取access_token
通过应用appid与appsecret与之前的code，换取access_token和用户openid等
```
https://api.weixin.qq.com/sns/oauth2/access_token?
    appid=APPID&
    secret=SECRET&
    code=CODE&
    grant_type=authorization_code
```