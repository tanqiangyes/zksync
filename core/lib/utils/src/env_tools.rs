use std::{env, iter::FromIterator, str::FromStr};

/// Obtains the environment variable value.
/// Panics if there is no environment variable with provided name set.
/// 获取环境变量，如果不存在相应的环境变量，则会panic
pub fn get_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|e| panic!("Env var {} missing, {}", name, e))//获取，如果存在则unwarp，出错则panic
}

/// Obtains the environment variable value and parses it using the `FromStr` type implementation.
/// Panics if there is no environment variable with provided name set, or the value cannot be parsed.
/// 获取环境变量值并使用FromStr类型实现对其进行解析。 如果没有设置提供名称的环境变量，或者无法解析该值，则会出现恐慌
pub fn parse_env<F>(name: &str) -> F //范型F
where
    F: FromStr,//f本身实现了FromStr trait
    F::Err: std::fmt::Debug,//f中的Err实现了Debug trait
{
    get_env(name)
        .parse()
        .unwrap_or_else(|e| panic!("Failed to parse environment variable {}: {:?}", name, e))
}

/// Similar to `parse_env`, but also takes a function to change the variable value before parsing.
/// 跟parse_env类似，但是拥有一个函数去处理数据
pub fn parse_env_with<T, F>(name: &str, f: F) -> T
where
    T: FromStr,
    T::Err: std::fmt::Debug,
    F: FnOnce(&str) -> &str,//只能被调用一次
{
    let env_var = get_env(name);

    f(&env_var)
        .parse()
        .unwrap_or_else(|e| panic!("Failed to parse environment variable {}: {:?}", name, e))
}

/// Obtains the environment variable value and on success parses it using the `FromStr` type implementation.
/// Panics if value cannot be parsed.
/// 获取环境变量值并在成功时使用FromStr类型实现对其进行解析。 如果无法解析值，则会出现恐慌。
pub fn parse_env_if_exists<F>(name: &str) -> Option<F>
where
    F: FromStr,
    F::Err: std::fmt::Debug,
{
    env::var(name)
        .map(|var| {
            var.parse().unwrap_or_else(|e| {
                panic!("Failed to parse environment variable {}: {:?}", name, e)
            })
        })
        .ok()
}

/// Obtains the environment comma separated variables into collection.
/// 返回迭代器
pub fn parse_env_to_collection<F, I>(name: &str) -> F
where
    I: FromStr,
    I::Err: std::fmt::Debug,
    F: FromIterator<I>,//迭代器
{
    get_env(name)
        .split(',')
        .map(|p| p.parse::<I>().unwrap())
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_env_tools() {
        const KEY: &str = "KEY";
        // Our test environment variable.
        env::set_var(KEY, "123");
        assert_eq!(get_env(KEY), "123");
        assert_eq!(parse_env::<i32>(KEY), 123);
        assert_eq!(parse_env_if_exists::<i32>(KEY), Some(123));

        env::remove_var(KEY);
        assert_eq!(parse_env_if_exists::<i32>(KEY), None);

        env::set_var(KEY, "ABC123");
        let parsed: i32 = parse_env_with(KEY, |key| &key[3..]);
        assert_eq!(parsed, 123);
    }
}
