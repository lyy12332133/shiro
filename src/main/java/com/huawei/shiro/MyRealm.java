package com.huawei.shiro;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * Created by dllo on 17/12/1.
 */
public class MyRealm extends AuthorizingRealm {
    // 自定义Realm
    // 系统提供了Realm接口, 但是常用来说需要继承AuthorizingRealm
    // 因为同时提供了授权和认证方法


    //方便做处理
    @Override
    public String getName() {
        return "myrealm";
    }

    //支持那种token类型
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }

    @Override
    // 授权
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    @Override
    // 认证
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        // 获得用户此次输入的用户名
        String username = (String) authenticationToken.getPrincipal();

        // 此处应该拿username去数据库查询, 是否存在该用户

        // ===>下面为模拟代码<===
        if (!"wangwu".equals(username)) {
            throw new UnknownAccountException("用户名不存在");
        }
        //====>模拟结束<====
        //获取用户输入的密码
        String password = new String((char[]) authenticationToken.getCredentials());
        if (!"1234".equals(password)) {
            throw new IncorrectCredentialsException("密码错误");
        }

        // 返回认证成功的信息
        return new SimpleAuthenticationInfo(username, password, getName());
    }
}
