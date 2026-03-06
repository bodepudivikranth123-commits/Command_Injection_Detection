#include <clang/AST/AST.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/ASTConsumers.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Support/raw_ostream.h>

#include <set>
#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>

using namespace clang;
using namespace clang::tooling;

enum Severity {
    LOW,
    MEDIUM,
    HIGH
};

struct Finding {
    std::string variable;
    std::string sink;
    Severity severity;
    unsigned sinkLine;
    unsigned sourceLine;
};

class TaintVisitor : public RecursiveASTVisitor<TaintVisitor> {
private:
    ASTContext *context;

    std::set<std::string> taintedVars;
    std::map<std::string, unsigned> taintSourceLine;

    std::vector<Finding> findings;

    bool isInputFunction(const std::string &name) {
        return name == "scanf" || name == "gets" || name == "fgets";
    }

    bool isHighRiskSink(const std::string &name) {
        return name == "system" || name == "popen" || name == "execvp";
    }
    bool isMediumRiskSink(const std::string &name) {
    return name == "sprintf" || name == "strcpy" || name == "strcat";
    }
public:
    explicit TaintVisitor(ASTContext *ctx) : context(ctx) {}

    /* ================== VISIT CALL EXPR ================== */
    bool VisitCallExpr(CallExpr *call) {
        if (CallExpr *callExpr = dyn_cast<CallExpr>(call)) {
    const FunctionDecl *callee = callExpr->getDirectCallee();
    if (callee) {
        llvm::errs() << "Detected function call: "
                     << callee->getNameAsString() << "\n";
    }
}
        const FunctionDecl *callee = call->getDirectCallee();
        if (!callee) return true;

        std::string fname = callee->getNameAsString();

        /* ----------- C STYLE INPUT SOURCES ----------- */
        if (isInputFunction(fname)) {
            unsigned taintIndex = (fname == "scanf") ? 1 : 0;
            if (call->getNumArgs() <= taintIndex) return true;

            Expr *arg = call->getArg(taintIndex)->IgnoreImpCasts();

            if (DeclRefExpr *dre = dyn_cast<DeclRefExpr>(arg)) {
                std::string var = dre->getNameInfo().getAsString();
                taintedVars.insert(var);

                unsigned line = context->getSourceManager()
                    .getSpellingLineNumber(call->getExprLoc());
                taintSourceLine[var] = line;
            }
        }

        /* ----------- HIGH RISK SINKS ----------- */
        if (isHighRiskSink(fname) && call->getNumArgs() > 0) {

            Expr *arg = call->getArg(0)->IgnoreImpCasts();

            // Case 1: system(var)
            if (DeclRefExpr *dre = dyn_cast<DeclRefExpr>(arg)) {
                std::string var = dre->getNameInfo().getAsString();
                if (taintedVars.count(var)) {
                    reportFinding(var, fname, HIGH, call);
                }
            }

            // Case 2: system(var.c_str())
            if (CXXMemberCallExpr *memberCall = dyn_cast<CXXMemberCallExpr>(arg)) {

                Expr *base = memberCall->getImplicitObjectArgument()
                                  ->IgnoreImpCasts();

                if (DeclRefExpr *dre = dyn_cast<DeclRefExpr>(base)) {
                    std::string var = dre->getNameInfo().getAsString();
                    if (taintedVars.count(var)) {
                        reportFinding(var, fname, HIGH, call);
                    }
                }
            }
        }
         /* ----------- MEDIUM RISK SINKS ----------- */
        if (isMediumRiskSink(fname) && call->getNumArgs() > 0) {

         // For strcpy(dest, src) → src is last argument
        Expr *arg = call->getArg(call->getNumArgs() - 1);
        arg = arg->IgnoreImpCasts();

         if (DeclRefExpr *dre = dyn_cast<DeclRefExpr>(arg)) {

        std::string var = dre->getNameInfo().getAsString();

        if (taintedVars.count(var)) {
            reportFinding(var, fname, MEDIUM, call);
        }
    }
}
        /* ----------- C++ cin SOURCE ----------- */
        if (CXXOperatorCallExpr *opCall = dyn_cast<CXXOperatorCallExpr>(call)) {

            if (opCall->getOperator() == OO_GreaterGreater) {

                // RHS is the variable receiving input
                Expr *arg = opCall->getArg(1)->IgnoreImpCasts();

                if (DeclRefExpr *dre = dyn_cast<DeclRefExpr>(arg)) {
                    std::string var = dre->getNameInfo().getAsString();

                    taintedVars.insert(var);
                    
                    unsigned line = context->getSourceManager()
                        .getSpellingLineNumber(call->getExprLoc());
                    taintSourceLine[var] = line;
                }
            }
        }

        return true;
    }

    /* ================== ASSIGNMENT PROPAGATION ================== */
    bool VisitBinaryOperator(BinaryOperator *op) {

        if (!op->isAssignmentOp()) return true;

        Expr *lhs = op->getLHS()->IgnoreImpCasts();
        Expr *rhs = op->getRHS()->IgnoreImpCasts();

        if (DeclRefExpr *rhsVar = dyn_cast<DeclRefExpr>(rhs)) {

            std::string rhsName = rhsVar->getNameInfo().getAsString();

            if (taintedVars.count(rhsName)) {

                if (DeclRefExpr *lhsVar = dyn_cast<DeclRefExpr>(lhs)) {

                    std::string lhsName = lhsVar->getNameInfo().getAsString();

                    taintedVars.insert(lhsName);
                    taintSourceLine[lhsName] = taintSourceLine[rhsName];
                }
            }
        }

        return true;
    }

    /* ================== REPORT FUNCTION ================== */
    void reportFinding(const std::string &var,
                       const std::string &sink,
                       Severity severity,
                       CallExpr *call) {

        unsigned sinkLine = context->getSourceManager()
            .getSpellingLineNumber(call->getExprLoc());

        findings.push_back({
            var,
            sink + "()",
            severity,
            sinkLine,
            taintSourceLine[var]
        });
    }

    /* ================== FINAL REPORT ================== */
    void report() {

        if (findings.empty()) {
            llvm::outs() << "[OK] No vulnerabilities detected\n";
            return;
        }

        for (auto &f : findings) {

            llvm::outs() << "[VULNERABILITY] Command Injection\n";

            if (f.severity == HIGH)
                llvm::outs() << "[SEVERITY] HIGH\n";
            else if (f.severity == MEDIUM)
                llvm::outs() << "[SEVERITY] MEDIUM\n";
            else
                llvm::outs() << "[SEVERITY] LOW\n";

            llvm::outs() << "[SINK] " << f.sink << "\n";
            llvm::outs() << "[SINK LINE] " << f.sinkLine << "\n";
            llvm::outs() << "[TAINTED VARIABLE] " << f.variable << "\n";
            llvm::outs() << "[SOURCE LINE] " << f.sourceLine << "\n\n";
        }
    }
};

/* ================== AST CONSUMER ================== */
class TaintConsumer : public ASTConsumer {
private:
    TaintVisitor visitor;
public:
    explicit TaintConsumer(ASTContext *ctx) : visitor(ctx) {}

    void HandleTranslationUnit(ASTContext &ctx) override {
        visitor.TraverseDecl(ctx.getTranslationUnitDecl());
        visitor.report();
    }
};

/* ================== FRONTEND ACTION ================== */
class TaintAction : public ASTFrontendAction {
public:
    std::unique_ptr<ASTConsumer>
    CreateASTConsumer(CompilerInstance &CI, StringRef) override {
        return std::make_unique<TaintConsumer>(&CI.getASTContext());
    }
};

/* ================== MAIN ================== */
int main(int argc, const char **argv) {

    if (argc < 2) {
        llvm::errs() << "Usage: taint_analysis <source-file>\n";
        return 1;
    }

    std::ifstream file(argv[1]);
    std::stringstream buffer;
    buffer << file.rdbuf();

    runToolOnCode(std::make_unique<TaintAction>(), buffer.str());

    return 0;
}