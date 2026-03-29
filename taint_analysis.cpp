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

/* ================= ENUM ================= */

enum Severity { LOW, MEDIUM, HIGH };

/* ================= STRUCT ================= */

struct Finding {
    std::string variable;
    std::string sink;
    Severity severity;
    unsigned sinkLine;
    unsigned sourceLine;
};

/* ================= VISITOR ================= */

class TaintVisitor : public RecursiveASTVisitor<TaintVisitor> {

private:

    ASTContext *context;

    std::set<std::string> taintedVars;
    std::map<std::string, unsigned> taintSourceLine;
    std::map<std::string, std::string> taintFlow;

    std::vector<Finding> findings;
    std::set<std::string> reported;

    /* -------- INPUT SOURCES -------- */

    bool isInputFunction(const std::string &name) {
        return name == "scanf" || name == "fscanf" ||
               name == "gets" || name == "fgets" ||
               name == "getline" || name == "getenv" ||
               name == "read" || name == "recv";
    }

    /* -------- HIGH RISK SINK -------- */

    bool isHighRiskSink(const std::string &name) {
        return name == "system" || name == "popen" ||
               name == "execvp" || name == "execv" ||
               name == "execve" || name == "execl" ||
               name == "execlp";
    }

    /* -------- MEDIUM RISK SINK -------- */

    bool isMediumRiskSink(const std::string &name) {
        return name == "sprintf" || name == "snprintf";
    }

public:

    explicit TaintVisitor(ASTContext *ctx) : context(ctx) {}

    /* ================= argv DETECTION ================= */

    bool VisitDeclRefExpr(DeclRefExpr *dre) {

        std::string var = dre->getNameInfo().getAsString();

        if (var == "argv") {
            taintedVars.insert("argv");

            unsigned line =
                context->getSourceManager()
                    .getSpellingLineNumber(dre->getExprLoc());

            taintSourceLine["argv"] = line;
        }

        return true;
    }

    /* ================= CALL VISIT ================= */

    bool VisitCallExpr(CallExpr *call) {

        const FunctionDecl *callee = call->getDirectCallee();
        if (!callee) return true;

        std::string fname = callee->getNameAsString();

        /* -------- INPUT SOURCES -------- */

        if (isInputFunction(fname)) {

            unsigned idx =
                (fname == "scanf" || fname == "fscanf") ? 1 : 0;

            if (call->getNumArgs() <= idx) return true;

            Expr *arg = call->getArg(idx)->IgnoreImpCasts();

            if (DeclRefExpr *dre = dyn_cast<DeclRefExpr>(arg)) {

                std::string var = dre->getNameInfo().getAsString();

                taintedVars.insert(var);

                unsigned line =
                    context->getSourceManager()
                        .getSpellingLineNumber(call->getExprLoc());

                taintSourceLine[var] = line;
            }
        }

        /* -------- strcpy / strcat propagation -------- */

        if (fname == "strcpy" || fname == "strncpy" ||
            fname == "strcat" || fname == "strncat") {

            if (call->getNumArgs() >= 2) {

                Expr *dest = call->getArg(0)->IgnoreImpCasts();
                Expr *src  = call->getArg(1)->IgnoreImpCasts();

                if (DeclRefExpr *srcVar = dyn_cast<DeclRefExpr>(src)) {

                    std::string srcName = srcVar->getNameInfo().getAsString();

                    if (taintedVars.count(srcName)) {

                        if (DeclRefExpr *destVar =
                            dyn_cast<DeclRefExpr>(dest)) {

                            std::string destName =
                                destVar->getNameInfo().getAsString();

                            taintedVars.insert(destName);
                            taintSourceLine[destName] =
                                taintSourceLine[srcName];
                            taintFlow[destName] = srcName;
                        }
                    }
                }
            }
        }

        /* -------- snprintf propagation -------- */

        if (fname == "snprintf" && call->getNumArgs() >= 3) {

            Expr *dest = call->getArg(0)->IgnoreImpCasts();

            for (unsigned i = 2; i < call->getNumArgs(); i++) {

                Expr *arg = call->getArg(i)->IgnoreImpCasts();

                if (DeclRefExpr *dre = dyn_cast<DeclRefExpr>(arg)) {

                    std::string var = dre->getNameInfo().getAsString();

                    if (taintedVars.count(var)) {

                        if (DeclRefExpr *destVar =
                            dyn_cast<DeclRefExpr>(dest)) {

                            std::string destName =
                                destVar->getNameInfo().getAsString();

                            taintedVars.insert(destName);
                            taintSourceLine[destName] =
                                taintSourceLine[var];
                            taintFlow[destName] = var;
                        }
                    }
                }
            }
        }

        /* -------- HIGH RISK SINK -------- */

        if (isHighRiskSink(fname)) {

            for (unsigned i = 0; i < call->getNumArgs(); i++) {

                Expr *arg = call->getArg(i)->IgnoreImpCasts();

                /* -------- CONSTANT COMMAND -------- */

                if (StringLiteral *str = dyn_cast<StringLiteral>(arg)) {

                    std::string val = str->getString().str();

                    if (val.find(";") != std::string::npos ||
                        val.find("&&") != std::string::npos ||
                        val.find("|") != std::string::npos) {

                        reportFinding("CONST_CMD", fname, HIGH, call);
                    }
                }

                /* -------- VARIABLE -------- */

                if (DeclRefExpr *dre = dyn_cast<DeclRefExpr>(arg)) {

                    std::string var = dre->getNameInfo().getAsString();

                    if (taintedVars.count(var))
                        reportFinding(var, fname, HIGH, call);
                }

                /* -------- argv[index] FIX -------- */

                if (ArraySubscriptExpr *arr =
                        dyn_cast<ArraySubscriptExpr>(arg)) {

                    Expr *base = arr->getBase()->IgnoreImpCasts();

                    if (DeclRefExpr *dre =
                        dyn_cast<DeclRefExpr>(base)) {

                        std::string var =
                            dre->getNameInfo().getAsString();

                        if (var == "argv") {
                            reportFinding("argv", fname, HIGH, call);
                        }
                    }
                }

                /* -------- cmd.c_str() -------- */

                if (CXXMemberCallExpr *m =
                    dyn_cast<CXXMemberCallExpr>(arg)) {

                    Expr *base =
                        m->getImplicitObjectArgument()->IgnoreImpCasts();

                    if (DeclRefExpr *dre =
                        dyn_cast<DeclRefExpr>(base)) {

                        std::string var =
                            dre->getNameInfo().getAsString();

                        if (taintedVars.count(var))
                            reportFinding(var, fname, HIGH, call);
                    }
                }

                /* -------- getenv -------- */

                if (CallExpr *inner = dyn_cast<CallExpr>(arg)) {

                    const FunctionDecl *c2 = inner->getDirectCallee();

                    if (c2 && c2->getNameAsString() == "getenv") {

                        reportFinding("ENV_VAR", fname, HIGH, call);
                    }
                }
            }
        }

        /* -------- MEDIUM RISK -------- */

        if (isMediumRiskSink(fname)) {

            for (auto *arg : call->arguments()) {

                arg = arg->IgnoreImpCasts();

                if (DeclRefExpr *dre = dyn_cast<DeclRefExpr>(arg)) {

                    std::string var = dre->getNameInfo().getAsString();

                    if (taintedVars.count(var))
                        reportFinding(var, fname, MEDIUM, call);
                }
            }
        }

        /* -------- C++ cin -------- */

        if (CXXOperatorCallExpr *op =
                dyn_cast<CXXOperatorCallExpr>(call)) {

            if (op->getOperator() == OO_GreaterGreater) {

                Expr *arg = op->getArg(1)->IgnoreImpCasts();

                if (DeclRefExpr *dre = dyn_cast<DeclRefExpr>(arg)) {

                    std::string var = dre->getNameInfo().getAsString();

                    taintedVars.insert(var);

                    unsigned line =
                        context->getSourceManager()
                            .getSpellingLineNumber(call->getExprLoc());

                    taintSourceLine[var] = line;
                }
            }
        }

        return true;
    }

    /* ================= ASSIGNMENT ================= */

    bool VisitBinaryOperator(BinaryOperator *op) {

        if (!op->isAssignmentOp()) return true;

        Expr *lhs = op->getLHS()->IgnoreImpCasts();
        Expr *rhs = op->getRHS()->IgnoreImpCasts();

        if (DeclRefExpr *rhsVar = dyn_cast<DeclRefExpr>(rhs)) {

            std::string rhsName = rhsVar->getNameInfo().getAsString();

            if (taintedVars.count(rhsName)) {

                if (DeclRefExpr *lhsVar = dyn_cast<DeclRefExpr>(lhs)) {

                    std::string lhsName =
                        lhsVar->getNameInfo().getAsString();

                    taintedVars.insert(lhsName);
                    taintSourceLine[lhsName] =
                        taintSourceLine[rhsName];
                    taintFlow[lhsName] = rhsName;
                }
            }
        }

        return true;
    }

    /* ================= REPORT ================= */

    void reportFinding(const std::string &var,
                       const std::string &sink,
                       Severity severity,
                       CallExpr *call) {

        unsigned line =
            context->getSourceManager()
                .getSpellingLineNumber(call->getExprLoc());

        std::string key = var + sink + std::to_string(line);

        if (reported.count(key)) return;

        reported.insert(key);

        findings.push_back({
            var, sink + "()", severity,
            line, taintSourceLine[var]
        });
    }

    /* ================= FINAL OUTPUT ================= */

    void report() {

        if (findings.empty()) {
            llvm::outs() << "[OK] No vulnerabilities detected\n";
            return;
        }

        for (auto &f : findings) {

            llvm::outs() << "[VULNERABILITY] Command Injection\n";

            llvm::outs() << "[SEVERITY] "
                         << (f.severity == HIGH ? "HIGH" :
                             f.severity == MEDIUM ? "MEDIUM" : "LOW") << "\n";

            llvm::outs() << "[SINK] " << f.sink << "\n";
            llvm::outs() << "[SINK LINE] " << f.sinkLine << "\n";
            llvm::outs() << "[TAINTED VARIABLE] " << f.variable << "\n";
            llvm::outs() << "[SOURCE LINE] " << f.sourceLine << "\n";

            llvm::outs() << "[TAINT FLOW] ";

            std::string current = f.variable;

            while (taintFlow.count(current)) {
                llvm::outs() << current << " <- ";
                current = taintFlow[current];
            }

            llvm::outs() << current << "\n\n";
        }
    }
};

/* ================= CONSUMER ================= */

class TaintConsumer : public ASTConsumer {

private:
    TaintVisitor visitor;

public:

    explicit TaintConsumer(ASTContext *ctx)
        : visitor(ctx) {}

    void HandleTranslationUnit(ASTContext &ctx) override {

        visitor.TraverseDecl(ctx.getTranslationUnitDecl());
        visitor.report();
    }
};

/* ================= ACTION ================= */

class TaintAction : public ASTFrontendAction {

public:

    std::unique_ptr<ASTConsumer>
    CreateASTConsumer(CompilerInstance &CI, StringRef) override {

        return std::make_unique<TaintConsumer>(&CI.getASTContext());
    }
};

/* ================= MAIN ================= */

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
