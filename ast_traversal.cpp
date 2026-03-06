#include "clang/AST/AST.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/raw_ostream.h"
#include <fstream>
#include <sstream>

using namespace clang;
class ASTVisitor : public RecursiveASTVisitor<ASTVisitor> {
    ASTContext *Context;

public:
    explicit ASTVisitor(ASTContext *Context) : Context(Context) {}

    bool isUserCode(SourceLocation Loc) {
        const SourceManager &SM = Context->getSourceManager();
        return SM.isWrittenInMainFile(SM.getExpansionLoc(Loc));
    }

    bool VisitFunctionDecl(FunctionDecl *FD) {
        if (FD->hasBody() && isUserCode(FD->getLocation())) {
            llvm::outs() << "Function: "
                         << FD->getNameAsString() << "\n";
        }
        return true;
    }

    bool VisitCallExpr(CallExpr *CE) {
        if (!isUserCode(CE->getExprLoc()))
            return true;

        if (FunctionDecl *FD = CE->getDirectCallee()) {
            llvm::outs() << "Function Call: "
                         << FD->getNameAsString() << "\n";
        }
        return true;
    }
};

class ASTConsumerImpl : public ASTConsumer {
public:
    void HandleTranslationUnit(ASTContext &Context) override {
        ASTVisitor Visitor(&Context);
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
    }
};


class ASTAction : public ASTFrontendAction {
public:
    std::unique_ptr<ASTConsumer>
    CreateASTConsumer(CompilerInstance &, StringRef) override {
        return std::make_unique<ASTConsumerImpl>();
    }
};



int main(int argc, const char **argv) {
    if (argc < 2) {
        llvm::errs() << "Usage: ast_traversal <source-file>\n";
        return 1;
    }

    std::ifstream inputFile(argv[1]);
    if (!inputFile) {
        llvm::errs() << "Cannot open file\n";
        return 1;
    }

    std::stringstream buffer;
    buffer << inputFile.rdbuf();

    clang::tooling::runToolOnCode(
        std::make_unique<ASTAction>(),
        buffer.str()
    );

    return 0;
}
