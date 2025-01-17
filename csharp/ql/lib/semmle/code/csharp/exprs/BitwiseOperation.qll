/**
 * Provides all bitwise operation classes.
 *
 * All bitwise operations have the common base class `BitwiseOperation`.
 */

import Expr

/**
 * A bitwise operation. Either a unary bitwise operation (`UnaryBitwiseOperation`)
 * or a binary bitwise operation (`BinaryBitwiseOperation`).
 */
class BitwiseOperation extends Operation, @bit_expr { }

/**
 * A unary bitwise operation, that is, a bitwise complement operation
 * (`ComplementExpr`).
 */
class UnaryBitwiseOperation extends BitwiseOperation, UnaryOperation, @un_bit_op_expr { }

/**
 * A bitwise complement operation, for example `~x`.
 */
class ComplementExpr extends UnaryBitwiseOperation, @bit_not_expr {
  override string getOperator() { result = "~" }

  override string getAPrimaryQlClass() { result = "ComplementExpr" }
}

/**
 * A binary bitwise operation. Either a bitwise-and operation
 * (`BitwiseAndExpr`), a bitwise-or operation (`BitwiseOrExpr`),
 * a bitwise exclusive-or operation (`BitwiseXorExpr`), a left-shift
 * operation (`LShiftExpr`), or a right-shift operation (`RShiftExpr`).
 */
class BinaryBitwiseOperation extends BitwiseOperation, BinaryOperation, @bin_bit_op_expr {
  override string getOperator() { none() }
}

/**
 * A left-shift operation, for example `x << y`.
 */
class LShiftExpr extends BinaryBitwiseOperation, @lshift_expr {
  override string getOperator() { result = "<<" }

  override string getAPrimaryQlClass() { result = "LShiftExpr" }
}

/**
 * A right-shift operation, for example `x >> y`.
 */
class RShiftExpr extends BinaryBitwiseOperation, @rshift_expr {
  override string getOperator() { result = ">>" }

  override string getAPrimaryQlClass() { result = "RShiftExpr" }
}

/**
 * A bitwise-and operation, for example `x & y`.
 */
class BitwiseAndExpr extends BinaryBitwiseOperation, @bit_and_expr {
  override string getOperator() { result = "&" }

  override string getAPrimaryQlClass() { result = "BitwiseAndExpr" }
}

/**
 * A bitwise-or operation, for example `x | y`.
 */
class BitwiseOrExpr extends BinaryBitwiseOperation, @bit_or_expr {
  override string getOperator() { result = "|" }

  override string getAPrimaryQlClass() { result = "BitwiseOrExpr" }
}

/**
 * A bitwise exclusive-or operation, for example `x ^ y`.
 */
class BitwiseXorExpr extends BinaryBitwiseOperation, @bit_xor_expr {
  override string getOperator() { result = "^" }

  override string getAPrimaryQlClass() { result = "BitwiseXorExpr" }
}
