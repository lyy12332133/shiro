package com.huawei.test;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Test;
import sun.security.provider.MD5;

import java.util.Arrays;

/**
 * Created by dllo on 17/12/1.
 */
public class MainTest {

    @Test
    public void test1() {

        //1. 构建SecurityManager工厂
        // IniSecurityManagerFactory可以从ini文件初始化SecurityManager环境
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro_realm.ini");

        //2. 通过工厂创建一个SecurityManager对象
        SecurityManager securityManager = factory.getInstance();

        //3. 将manager设置到运行环境中
        SecurityUtils.setSecurityManager(securityManager);

        //4. 创建一个Subject实例
        //      Subject认证的过程需要先配置SecurityManager
        Subject subject = SecurityUtils.getSubject();

        //5. 创建一个token(令牌), 记录用户认证的身份和凭证(用户名/密码)
        UsernamePasswordToken token = new UsernamePasswordToken("wangwu", "1234");

        try {
            subject.login(token);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("认证失败");
        }

//        subject.logout(); // 登出
        boolean result = subject.isAuthenticated();
        System.out.println("用户认证的状态: " + result);

        // 认证的执行流程
        // 1. 创建token, 包含用户提交的认证信息即账号和密码
        // 2. 将token交给subject.login方法, 最终由SecurityManager通过Authenticator进行认证
        // 3. Authenticator 的实现类调用Realm从ini配置文件中读取用户真正的用户名和密码(IniRealm)
        // 4. IniRealm先根据token中的账号去ini文件中找账号, 如果找不到就给上述实现类返回null.
        //      如果找到账号, 就继续匹配密码. 两者都匹配, 认证成功

        // 常见的异常信息:
        // IncorrectCredentialsException: 密码错误
        // UnknownAccountException : 用户名不存在异常
        // DisableAccountException: 账户被禁用
        // LockedAccountException: 账户被锁定
        // ExcessiveAttemptsException: 登录失败次数过多
    }

    @Test
    public void test2() {
        // 测试MD5
        String pwdMD5 = new Md5Hash("111111").toString();
        System.out.println(pwdMD5);

        // 加盐
        String pwdSalt1 = new Md5Hash("12332133", "lyy").toString();
        String pwdSalt2 = new Md5Hash("yangyang", "lyy@@").toString();
        System.out.println(pwdSalt1);
        System.out.println(pwdSalt2);
    }

//    @RequiresRoles("CEO")
//    @RequiresPermissions("user:update")
    @Test
    public void test3() {
        // 授权

        //1. 构建SecurityManager工厂
        // IniSecurityManagerFactory可以从ini文件初始化SecurityManager环境
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro_per_realm.ini");

        //2. 通过工厂创建一个SecurityManager对象
        SecurityManager securityManager = factory.getInstance();

        //3. 将manager设置到运行环境中
        SecurityUtils.setSecurityManager(securityManager);

        //4. 创建一个Subject实例
        //      Subject认证的过程需要先配置SecurityManager
        Subject subject = SecurityUtils.getSubject();

        //5. 创建一个token(令牌), 记录用户认证的身份和凭证(用户名/密码)
        UsernamePasswordToken token = new UsernamePasswordToken("wangwu", "666");

        try {
            subject.login(token);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("认证失败");
        }

//        subject.logout(); // 登出
        boolean result = subject.isAuthenticated();
        System.out.println("用户认证的状态: " + result);

        // 用户授权检测, 基于角色的授权
        System.out.println("用户是否拥有一个角色: " + subject.hasRole("STUDENT"));

        System.out.println("用户是否拥有多个角色: " + subject.hasAllRoles(Arrays.asList("STUDENT","HR")));

        // 基于权限授权
        System.out.println("用户是否拥有某一个权限: " + subject.isPermitted("user:create"));

        System.out.println("用户是否拥有对应的所有权限: " + subject.isPermittedAll("user:create","user:delete"));

        // 检测角色/权限

        // check系列的方法:
        // 如果符合条件, 什么都不会发生.
        // 如果不符合,报异常(UnauthorizedException)
        subject.checkRole("CEO");



        // shiro支持3种方式进行权限的控制(包含权限和角色)

        /*
        1. 编程式: 写if/else授权代码, 通过subject进行管理
         Subject subject = SecurityUtils.getSubject();
        if (subject.hasRole("CEO") || subject.isPermitted("user:create")) {
            // 有权限
        } else {
            //无权限
        }

        2. 注解式: 在java方法上放置相应的注解
        @RequiresRoles("CEO")
        @RequiresPermissions("user:update")

        3. JSP里, shiro提供了专门的标签
            <shiro:hasRole name="CEO">
                <%-- 有权限 --%>
            </shiro:hasRole>
        */
    }
}
