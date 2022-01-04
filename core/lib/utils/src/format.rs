// Built-in deps
use std::collections::VecDeque;//使用可增长的环形缓冲区实现的双端队列
use std::string::ToString;
// External deps
// Workspace deps

/// Formats amount in wei to tokens with precision.
/// Behaves just like ethers.utils.formatUnits
/// 将 wei 中的数量格式化为精确的标记。行为就像 ethers.utils.formatUnits
pub fn format_units(wei: impl ToString, units: u8) -> String {
    let mut chars: VecDeque<char> = wei.to_string().chars().collect();//声明一个双端队列，返回一个迭代器

    while chars.len() < units as usize {//强转为usize ,然后填充0
        chars.push_front('0');
    }
    chars.insert(chars.len() - units as usize, '.');//在index处插入.符号
    if *chars.front().unwrap() == '.' {//如果最前面为.号，则说明应该填充0
        chars.push_front('0');
    }
    while *chars.back().unwrap() == '0' {//如果最后面为0，则说明应该去掉无用的0
        chars.pop_back();
    }
    if *chars.back().unwrap() == '.' {//如果删完了，则应该追加一个0，保留小数点
        chars.push_back('0');
    }
    chars.iter().collect()//返回一个String
}

/// Formats amount in wei to tokens.
/// Behaves just like js ethers.utils.formatEther
/// 转换为wei单位
pub fn format_ether(wei: impl ToString) -> String {
    format_units(wei, 18)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_format_units() {
        // Test vector of (decimals, wei input, expected output)
        let vals = vec![
            (0, "1000000000000000100000", "1000000000000000100000.0"),
            (1, "0", "0.0"),
            (1, "11000000000000000000", "1100000000000000000.0"),
            (2, "0", "0.0"),
            (2, "1000000000000000100000", "10000000000000001000.0"),
            (4, "10001000000", "1000100.0"),
            (4, "10100000000000000000000", "1010000000000000000.0"),
            (4, "110", "0.011"),
            (6, "1000000000000000100000", "1000000000000000.1"),
            (8, "0", "0.0"),
            (8, "10100000000000000000000", "101000000000000.0"),
            (8, "110", "0.0000011"),
            (9, "10000000000000000001", "10000000000.000000001"),
            (9, "11000000", "0.011"),
            (9, "11000000000000000000", "11000000000.0"),
            (10, "10001000000", "1.0001"),
            (10, "20000000000000000000000", "2000000000000.0"),
            (11, "0", "0.0"),
            (11, "10100000000000000000000", "101000000000.0"),
            (12, "1000000000000000100000", "1000000000.0000001"),
            (12, "10001000000", "0.010001"),
            (12, "10010000000", "0.01001"),
            (12, "110", "0.00000000011"),
            (13, "10010000000", "0.001001"),
            (14, "10010000000", "0.0001001"),
            (14, "110", "0.0000000000011"),
            (15, "0", "0.0"),
            (17, "1000000000000000100000", "10000.000000000001"),
            (17, "10001000000", "0.00000010001"),
            (18, "1000000000000000100000", "1000.0000000000001"),
        ];

        for (dec, input, output) in vals {
            assert_eq!(format_units(&input, dec), output);
        }
    }
}
