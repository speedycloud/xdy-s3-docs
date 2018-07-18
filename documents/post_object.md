# PostObject

**PostObject** 使用HTML表单上传文件到指定bucket。Post作为Put的替代品，使得基于浏览器上传文件到`bucket`成为可能。`Post Object`的消息实体通过多重表单格式`（multipart/form-data）`编码，在`Put Object`操作中参数通过 HTTP 请求头传递，在`Post`操作中参数则作为消息实体中的表单域传递。

## 请求语法

```bash
POST / HTTP/1.1
Host: oss-cn-beijing.speedycloud.org
User-Agent: browser_data
Accept: file_types
Accept-Language: Regions
Accept-Encoding: encoding
Accept-Charset: character_set
Keep-Alive: 300
Connection: keep-alive
Content-Type: multipart/form-data; boundary=9431149156168
Content-Length: length

--9431149156168
Content-Disposition: form-data; name="key"

acl
--9431149156168
Content-Disposition: form-data; name="success_action_redirect"

success_redirect
--9431149156168
Content-Disposition: form-data; name="Content-Type"

content_type
--9431149156168
Content-Disposition: form-data; name="AWSAccessKeyId"

access-key-id
--9431149156168
Content-Disposition: form-data; name="Policy"

encoded_policy
--9431149156168
Content-Disposition: form-data; name="Signature"

signature=
--9431149156168
Content-Disposition: form-data; name="file"; filename="MyFilename.jpg"
Content-Type: image/jpeg

file_content
--9431149156168
Content-Disposition: form-data; name="submit"

Upload to XDY S3
--9431149156168--
```
## 表单域

| 名字 | 描述 | 必须 |
|---|---|---|
| AWSAccessKeyId | AWSAccessKeyId(即accesskey)是oss.speedycloud.cn分配给用户两个密钥 | 有条件的 |
| policy | policy规定了请求的表单域的合法性。不包含policy表单域的请求被认为是匿名请求，并且只能访问public-read-write的bucket。更详细描述请参考下文 Post Policy。默认值：无限制：当bucket非public-read-write或者提供了OSSAccessKeyId（或Signature）表单域时，必须提供该表单域。 | 有条件的 |
| Signature | 根据Access Key Secret和policy计算的签名信息，OSS验证该签名信息从而验证该Post请求的合法性。更详细描述请参考下文 Post Signature。默认值：无限制：当bucket非public-read-write或者提供了OSSAccessKeyId（或policy）表单域时，必须提供该表单域。 |      有条件的     |
| Cache-Control, Content-Type, Content-Disposition, Content-Encoding, Expires | REST请求头 | 可选 |
| file | 文件或文本内容，必须是表单中的最后一个域。浏览器会自动根据文件类型来设置Content-Type，会覆盖用户的设置。 OSS一次只能上传一个文件。 | 必须 |
| key | 上传文件的object名称。 | 必须 |
| success_action_redirect | 上传成功后客户端跳转到的URL | 可选 |
| success_action_status | success_action_redirect表单域时，该表单域指定了上传成功后返回给客户端的状态码。 接受值为200, 201, 204（默认）。 | 可选 |
| acl | 指定oss创建object时的访问权限。 | 可选 |

## 完整Python代码示例:

```python
# coding=utf8

import hashlib
import base64
import hmac
from optparse import OptionParser


def generate_base64(value):
    return base64.b64encode(value)


def generate_sign(key, policy):
    return base64.b64encode(hmac.new(key, policy, hashlib.sha1).digest())


def generate_form(bucket, endpoint, access_key_id, access_key_secret, out):
    # 1 构建一个Post Policy
    policy = '{"expiration":"2018-07-20T12:00:00.000Z","conditions":[{"bucket":"mytt"},["starts-with","$key","log/"], {"acl": "public-read"}]}'
    print("policy: %s" % policy)

    # 2 将Policy字符串进行base64编码
    base64policy = generate_base64(policy)
    print("base64_encode_policy: %s" % base64policy)

    # 3 用OSS的AccessKeySecret对编码后的Policy进行签名
    signature = generate_sign(access_key_secret, base64policy)

    # 4 构建上传的HTML页面
    form = '''
    <html>
        <meta http-equiv=content-type content="text/html; charset=UTF-8">
        <head><title>XDY表单上传(PostObject)</title></head>
        <body>
            <form  action="http://%s/%s" method="post" enctype="multipart/form-data">
                <input type="text" name="AWSAccessKeyId" value="%s">
                <input type="text" name="policy" value="%s">
                <input type="text" name="Signature" value="%s">
                <input type="text" name="key" value="log/${filename}">
                <input type="text" name="acl" value="public-read">
                <input name="file" type="file" id="file">
                <input name="submit" value="Upload" type="submit">
            </form>
        </body>
    </html>
    ''' % (endpoint, bucket, access_key_id, base64policy, signature)
    f = open(out, "wb")
    f.write(form)
    f.close()
    print("form is saved into %s" % out)


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("", "--bucket", dest="bucket", help="specify")
    parser.add_option("", "--endpoint", dest="endpoint", help="specify")
    parser.add_option("", "--accesskey", dest="accesskey", help="access_key")
    parser.add_option("", "--secretkey", dest="secretkey", help="secretkey")
    parser.add_option("", "--out", dest="out", help="out put form")
    (opts, args) = parser.parse_args()
    if opts.bucket and opts.endpoint and opts.accesskey and opts.secretkey and opts.out:
        generate_form(opts.bucket, opts.endpoint, opts.accesskey, opts.secretkey, opts.out)
    else:
        print "python %s --bucket=your-bucket --endpoint=oss-cn-beijing.speedycloud.org --accesskey=your-access-key-id --secretkey=your-access-key-secret --out=out-put-form-name" % __file__

```

将此段代码保存为 `form.py`，然后用 `python form.py` 来运行。

用法：

```bash
# python form.py --bucket=您的Bucket --endpoint=oss-cn-beijing.speedycloud.org  --accesskey=您的accesskey --secretkey=您的secretkey --out=输出的文件名
```
