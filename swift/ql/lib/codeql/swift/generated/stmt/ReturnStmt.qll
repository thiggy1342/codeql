// generated by codegen/codegen.py
private import codeql.swift.generated.Synth
private import codeql.swift.generated.Raw
import codeql.swift.elements.expr.Expr
import codeql.swift.elements.stmt.Stmt

module Generated {
  class ReturnStmt extends Synth::TReturnStmt, Stmt {
    override string getAPrimaryQlClass() { result = "ReturnStmt" }

    Expr getImmediateResult() {
      result =
        Synth::convertExprFromRaw(Synth::convertReturnStmtToRaw(this).(Raw::ReturnStmt).getResult())
    }

    final Expr getResult() { result = getImmediateResult().resolve() }

    final predicate hasResult() { exists(getResult()) }
  }
}
