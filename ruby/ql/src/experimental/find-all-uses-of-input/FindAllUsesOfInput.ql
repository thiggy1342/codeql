/**
 * @name finds all dataflows for specific user input
 * @description finds all dataflows for specific user input
 * @kind path-problem
 * @problem.severity error
 * @security-severity 5.0
 * @precision low
 * @id rb/find-all-uses-of-input
 * @tags security
 */

import codeql.ruby.AST
import codeql.ruby.DataFlow
import codeql.ruby.controlflow.CfgNodes
import codeql.ruby.frameworks.ActionController
import codeql.ruby.TaintTracking
import DataFlow::PathGraph

// any access to `params` calls in an action method
class SSNParam extends DataFlow::CallNode {
  SSNParam() {
    this.getMethodName() = "params" and
    this.asExpr().getExpr().getEnclosingMethod() instanceof ActionControllerActionMethod and
    this.getAnElementRead().getMethodName() = "ssn"
  }
}

class SSNParamConfig extends TaintTracking::Configuration {
  SSNParamConfig() { this = "SSNParamConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SSNParam
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(ExprNodes::ConditionalExprCfgNode c | c.getCondition() = sink.asExpr()) or
    exists(ExprNodes::CaseExprCfgNode c | c.getValue() = sink.asExpr())
  }
}

from SSNParamConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Manually checking HTTP verbs is an indication that multiple requests are routed to the same controller action. This could lead to bypassing necessary authorization methods and other protections, like CSRF protection. Prefer using different controller actions for each HTTP method and relying Rails routing to handle mapping resources and verbs to specific methods."
