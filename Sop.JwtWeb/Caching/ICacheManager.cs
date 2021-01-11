using System;
// ReSharper disable CheckNamespace

namespace Sop.Core.Caching
{
    /// <summary>
    /// 缓存管理接口
    /// </summary>
    public interface ICacheManager : IDisposable
    {
        /// <summary>
        /// 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="key"></param>
        /// <returns></returns>
        T Get<T>(string key);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <param name="cacheTime"></param>
        void Set(string key, object value, int cacheTime);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <param name="timeSpan"></param>
        void Set(string key, object value, TimeSpan timeSpan);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        bool IsSet(string key);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        void Remove(string key);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="pattern"></param>

        void RemoveByPattern(string pattern);
        /// <summary>
        /// 
        /// </summary>
        void Clear();
    }
}