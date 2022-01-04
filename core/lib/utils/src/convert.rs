use bigdecimal::BigDecimal;//十进制大数
use num::{
    bigint::ToBigInt,
    rational::Ratio,//两个数字之间的比率
    traits::{sign::Signed, Pow},
    BigUint,
};
//公开函数，将科学表示法ratio转换为BigDecimal， num为小数点表示，precision为10的次方， 返回bigdecimal类型的数字（常规的书写办法）
pub fn ratio_to_big_decimal(num: &Ratio<BigUint>, precision: usize) -> BigDecimal {
    let bigint = round_precision_raw_no_div(num, precision)
        .to_bigint()
        .unwrap();//转换为bigint
    BigDecimal::new(bigint, precision as i64)//转换为BigDecimal
}
//将BigDecimal类型的数字转换为科学计数法的数字
pub fn big_decimal_to_ratio(num: &BigDecimal) -> Result<Ratio<BigUint>, anyhow::Error> {
    let (big_int, exp) = num.as_bigint_and_exponent();//返回bigint和次方
    anyhow::ensure!(!big_int.is_negative(), "BigDecimal should be unsigned");//确保big_int是合法的
    let big_uint = big_int.to_biguint().unwrap();//转为无符号整数
    let ten_pow = BigUint::from(10_u32).pow(exp as u128);//生成次方
    Ok(Ratio::new(big_uint, ten_pow))//返回最终结果
}
//将科学计数法转换为常规书写形式
fn round_precision_raw_no_div(num: &Ratio<BigUint>, precision: usize) -> BigUint {
    let ten_pow = BigUint::from(10u32).pow(precision);
    (num * ten_pow).round().to_integer()
}
//将BigDecimal类型转换为科学计数法
pub fn round_precision(num: &Ratio<BigUint>, precision: usize) -> Ratio<BigUint> {
    let ten_pow = BigUint::from(10u32).pow(precision);//获取次方
    let numerator = (num * &ten_pow).trunc().to_integer();//生成小数位
    Ratio::new(numerator, ten_pow)//组合
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ratio_to_big_decimal() {
        let ratio = Ratio::from_integer(BigUint::from(0u32));
        let dec = ratio_to_big_decimal(&ratio, 1);
        assert_eq!(dec.to_string(), "0.0");
        let ratio = Ratio::from_integer(BigUint::from(1234u32));
        let dec = ratio_to_big_decimal(&ratio, 7);
        assert_eq!(dec.to_string(), "1234.0000000");
        // 4 divided by 9 is 0.(4).
        let ratio = Ratio::new(BigUint::from(4u32), BigUint::from(9u32));
        let dec = ratio_to_big_decimal(&ratio, 12);
        assert_eq!(dec.to_string(), "0.444444444444");
        // First 7 decimal digits of pi.
        let ratio = Ratio::new(BigUint::from(52163u32), BigUint::from(16604u32));
        let dec = ratio_to_big_decimal(&ratio, 6);
        assert_eq!(dec.to_string(), "3.141592");
    }

    #[test]
    fn test_big_decimal_to_ratio() {
        // Expect unsigned number.
        let dec = BigDecimal::from(-1);
        assert!(big_decimal_to_ratio(&dec).is_err());
        let expected = Ratio::from_integer(BigUint::from(0u32));
        let dec = BigDecimal::from(0);
        let ratio = big_decimal_to_ratio(&dec).unwrap();
        assert_eq!(ratio, expected);
        let expected = Ratio::new(BigUint::from(1234567u32), BigUint::from(10000u32));
        let dec = BigDecimal::from_str("123.4567").unwrap();
        let ratio = big_decimal_to_ratio(&dec).unwrap();
        assert_eq!(ratio, expected);
    }

    #[test]
    fn test_round_precision() {
        let ratio = Ratio::new(BigUint::from(4u32), BigUint::from(9u32));
        let rounded = round_precision(&ratio, 6);
        assert_eq!(ratio_to_big_decimal(&rounded, 6).to_string(), "0.444444");
        let ratio = Ratio::new(BigUint::from(355u32), BigUint::from(113u32));
        let rounded = round_precision(&ratio, 6);
        assert_eq!(ratio_to_big_decimal(&rounded, 6).to_string(), "3.141592");
        // 9.87648 with precision of 2 digits is 987 / 100.
        let ratio = Ratio::new(BigUint::from(123456u32), BigUint::from(12500u32));
        let rounded = round_precision(&ratio, 2);
        let expected = Ratio::new(BigUint::from(987u32), BigUint::from(100u32));
        assert_eq!(rounded, expected);
    }
}
