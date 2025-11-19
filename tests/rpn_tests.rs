use whirlpoolsum::util::evaluate_rpn_str;

#[test]
fn test_rpn_evaluator() {
    // 10 + 20 = 30
    assert_eq!(evaluate_rpn_str("10 20 +"), 30);

    // 10 * 20 = 200
    assert_eq!(evaluate_rpn_str("10 20 *"), 200);

    // (10 + 2) * 3 = 36
    assert_eq!(evaluate_rpn_str("10 2 + 3 *"), 36);

    // 100 / 2 = 50
    assert_eq!(evaluate_rpn_str("100 2 /"), 50);

    // 100 - 20 = 80
    assert_eq!(evaluate_rpn_str("100 20 -"), 80);
}
