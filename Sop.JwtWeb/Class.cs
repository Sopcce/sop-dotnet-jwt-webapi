using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Sop.Core.Caching;
using StackExchange.Redis;

namespace Sop.JwtWeb
{
    /// <summary>
    /// 
    /// </summary>
    public class JwtHelper
    {

    }

    /// <summary>
    /// 
    /// </summary>
    public static class StartupHelper
    {

        /// <summary>
        /// AddRedis
        /// </summary>
        /// <param name="services">IServiceCollection</param>
        /// <param name="configuration">IConfiguration</param>
        public static void AddCacheOrRedis(this IServiceCollection services, IConfiguration configuration)
        {
            #region Redis 或者缓存
            //注入 redis https://stackexchange.github.io/StackExchange.Redis/  
            var connStr = configuration.GetSection("RedisConfig:ConnectionString").Value;
            try
            {
                if (string.IsNullOrWhiteSpace(connStr))
                {
                    services.AddSingleton<ICacheManager>(new MemoryCacheManager());
                }
                else
                {
                    //TODO 如果连接不可以，只在程序重启动第一次调用判断，这是一个单例
                    var configurationOptions = ConfigurationOptions.Parse(connStr);
                    var connectionMultiplexer = ConnectionMultiplexer.Connect(connStr);
                    if (connectionMultiplexer.IsConnected)
                    {
                        services.AddSingleton<ICacheManager>(new RedisCacheManager(configurationOptions));
                    }
                    else
                    {
                        services.AddSingleton<ICacheManager>(new MemoryCacheManager());
                    }
                }
            }
            catch (Exception e)
            {
                // logger.Error(e, e.Message);
            }
            #endregion
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        public static void AddJwtSwagger(this IServiceCollection services, IConfiguration configuration)
        {
            string Issuer = configuration.GetSection("Authentication:JwtBearer:Audience").Value ?? "Audience";
            string IssuerSigningKey = "";
            string Audience = "";
            var jwtConfig = configuration.GetSection("Authentication:JwtBearer");

            services
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
                      {

                          options.SaveToken = true;
                          options.TokenValidationParameters = new TokenValidationParameters
                          {
                              ValidateIssuer = true,//是否验证Issuer
                              ValidateAudience = true,//是否验证Audience
                              ValidateLifetime = false,//是否验证失效时间
                              ValidateIssuerSigningKey = true,//是否验证SecurityKey
                              IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["IssuerSigningKey"])),
                              ValidIssuer = Issuer,
                              ValidAudience = configuration["Audience"],
                              //SaveSigninToken=false
                              //ValidateTokenReplay = false;
                              //    RequireExpirationTime = true;
                              //    RequireSignedTokens = true;
                              ClockSkew = TimeSpan.FromMinutes(5), //即ClockSkew的默认值为5分钟
                              ////这里采用动态验证的方式，在重新登陆时，刷新token，旧token就强制失效了
                              //AudienceValidator = (m, token, tokenParams) =>
                              //{
                              //    var mdsd = m; 
                              //    return m != null && m.FirstOrDefault().Equals(jwtConfig["Audience"]);
                              //}
                          };
                          options.Events = new JwtBearerEvents
                          {
                              OnMessageReceived = ctx =>
                              {
                                  // BUG 
                                  //var token = ctx.Request.Headers[Const.Authorization];
                                  //var jwtInfo = JwtHelper.SetJwt(token);
                                  //var userInfo = JwtHelper.GetUserIdentityByLoginName(jwtInfo.loginName);
                                  //if (userInfo != null)
                                  //{
                                  //    var newJwt = JwtHelper.GetJwt(userInfo);
                                  //    ctx.Response.Cookies.Delete("token_statsys", _cookieOptions);
                                  //    ctx.Response.Cookies.Append("token_statsys", newJwt, _cookieOptions);
                                  //    logger.Debug($"输出用户token:" + newJwt);
                                  //}
                                  return Task.CompletedTask;
                              },
                              OnTokenValidated = context =>
                              {
                                  var userId = context.Principal.Identity.Name;
                                  var user = JwtHelper.GetUserIdentityByLoginName(userId);
                                  if (user == null)
                                  {
                                      // return unauthorized if user no longer exists
                                      context.Fail("Unauthorized");
                                  }
                                  return Task.CompletedTask;
                              }
                          };
                      });

        }
    }
}
