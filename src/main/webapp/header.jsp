<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Active Directory Help Lookup Tool</title>
</head>
<body>
Active Directory Help Tool
<form action="Adhelp" method="get">
  User or Group: <input type="text" name="samAccountName"><br>
  Type (user or group)<select name="type">
    <option value="user">user</option>
    <option value="group">group</option>
  </select>
  <br>
  <input type="submit" value="Submit">
</form>