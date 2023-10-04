package com.lunarcell.authorizationServer.plugin;

import java.util.Date;
import java.util.Properties;

import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.plugin.Intercepts;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.plugin.Plugin;
import org.apache.ibatis.plugin.Signature;

import com.lunarcell.authorizationServer.model.ModelBase;

@Intercepts({ 
	@Signature(type = Executor.class, 
		method = "update", 
		args = { MappedStatement.class, Object.class }) })
public class RepoInterceptor implements Interceptor {

	@Override
	public Object intercept(Invocation invocation) throws Throwable {
	       MappedStatement stmt = (MappedStatement) invocation.getArgs()[0];  
	        Object param = invocation.getArgs()[1];
	        if (stmt == null) {
	            return invocation.proceed();
	        }
	        
	        if (stmt.getSqlCommandType().equals(SqlCommandType.INSERT)) {  
	            if (param != null && param instanceof ModelBase) {
	                ModelBase e = (ModelBase) param;
	                Date now = new Date();
                    e.setCreatedAt(now);
                    e.setUpdatedAt(now);
	            }
	        }
	        
	        if (stmt.getSqlCommandType().equals(SqlCommandType.UPDATE)) {  
	            if (param != null && param instanceof ModelBase) {
	                ModelBase e = (ModelBase) param;
                    e.setUpdatedAt(new Date());
	            }
	        }
	        
	        return invocation.proceed();
	}

	@Override
	public Object plugin(Object target) {
        return Plugin.wrap(target, this);  
	}

	@Override
	public void setProperties(Properties properties) {

	}

}
