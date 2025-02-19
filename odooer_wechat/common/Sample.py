#!/usr/bin/env python
from wechatpy import parse_message
from wechatpy.crypto import WeChatCrypto
from wechatpy.exceptions import InvalidSignatureException, InvalidAppIdException

if __name__ == "__main__":   

   encodingAESKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG" 
   token = "spamtest"
   nonce = "1320562132"
   appid = "wx2c2769f8efd9abc2"

   #测试解密接口
   timestamp = "1409735669"
   msg_sign  = "5d197aaffba7e9b25a30732f161a50dee96bd5fa"   
   from_xml = """<xml><ToUserName><![CDATA[gh_10f6c3c3ac5a]]></ToUserName><FromUserName><![CDATA[oyORnuP8q7ou2gfYjqLzSIWZf0rs]]></FromUserName><CreateTime>1409735668</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[abcdteT]]></Content><MsgId>6054768590064713728</MsgId><Encrypt><![CDATA[hyzAe4OzmOMbd6TvGdIOO6uBmdJoD0Fk53REIHvxYtJlE2B655HuD0m8KUePWB3+LrPXo87wzQ1QLvbeUgmBM4x6F8PGHQHFVAFmOD2LdJF9FrXpbUAh0B5GIItb52sn896wVsMSHGuPE328HnRGBcrS7C41IzDWyWNlZkyyXwon8T332jisa+h6tEDYsVticbSnyU8dKOIbgU6ux5VTjg3yt+WGzjlpKn6NPhRjpA912xMezR4kw6KWwMrCVKSVCZciVGCgavjIQ6X8tCOp3yZbGpy0VxpAe+77TszTfRd5RJSVO/HTnifJpXgCSUdUue1v6h0EIBYYI1BD1DlD+C0CR8e6OewpusjZ4uBl9FyJvnhvQl+q5rv1ixrcpCumEPo5MJSgM9ehVsNPfUM669WuMyVWQLCzpu9GhglF2PE=]]></Encrypt></xml>"""

   crypto = WeChatCrypto(token, encodingAESKey, appid)
   try:
      decrypted_xml = crypto.decrypt_message(
         from_xml,
         msg_sign,
         timestamp,
         nonce
      )
   except (InvalidAppIdException, InvalidSignatureException):
      # 处理异常或忽略
      pass

   msg = parse_message(decrypted_xml)
   print(msg)
