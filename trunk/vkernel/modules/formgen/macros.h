#pragma once

/* Constraint generation macros -- Eliminates some of the tedium of
 * generating STP formulas in text form. */

#define CG_TRUE \
   CgenOut(" TRUE ");

#define CG_FALSE \
   CgenOut(" FALSE ");

#define CG_BINOP(opstr, a, b) \
   CgenOut(opstr); CgenOut("("); a; CgenOut(", "); b; CgenOut(")");

#define CG_BINOP_TYPED(opstr, irType, a, b) \
   CgenOut(opstr); CgenOut("(%d, ", IRTYPE2BITS(irType)); a; CgenOut(", "); b; CgenOut(")");

#define CG_BINOP_INFIX(opstr, a, b) \
   CgenOut("("); a; CgenOut(" " opstr " "); b; CgenOut(")");

#define CG_UNOP(opstr, a) \
   CgenOut(opstr " "); a;

#define CG_EXTRACT(var, b1, b2) \
   ASSERT(b1 >= 0 && (b2) >= 0); \
   ASSERT(b1 >= (b2)); \
   var; CgenOut("[%d:%d]", b1, b2);

#define CG_EXTRACT_BYTE(var, bIdx) \
   CG_EXTRACT(var, (((bIdx+1) * 8)-1), (bIdx * 8));

/* XXX: eventually, get rid of the type parameter
 * requirement. */
#define CG_LO(irType, v) \
   CgenOut("("); v; CgenOut(")[%d:0]", (T2B(irType)/2)-1);

#define CG_HI(irType, v) \
   CgenOut("("); v; CgenOut(")[%d:%d]", T2B(irType)-1, T2B(irType)/2);

/* XXX: Need to remember variable types so that we know whether
 * to cast up or down. For now, assume down. */
#define CG_CAST(irType, v) \
   CgenOut("("); v; CgenOut(")[%d:0]", T2B(irType)-1);

#define CG_SX(irType, a) \
   CG_BINOP("BVSX", a, CG_DEC(IRTYPE2BITS(irType)))

#define CG_X(a, bits) \
   CG_BINOP_INFIX("@", CG_CONST_BITS(0, bits-1), a)

#define CG_XOR(a, b) \
   CG_BINOP("BVXOR", a, b)

#define CG_LT(a, b) \
   CG_BINOP("BVLT", a, b)

#define CG_SLT(a, b) \
   CG_BINOP("SBVLT", a, b)

#define CG_LE(a, b) \
   CG_BINOP("BVLE", a, b)

#define CG_SLE(a, b) \
   CG_BINOP("SBVLE", a, b)

#define CG_AND(a, b) \
   CG_BINOP_INFIX("&", a, b)

#define CG_OR(a, b) \
   CG_BINOP_INFIX("|", a, b)

#define CG_ADD(irType, a, b) \
   CG_BINOP_TYPED("BVPLUS", irType, a, b)

#define CG_SUB(irType, a, b) \
   CG_BINOP_TYPED("BVSUB", irType, a, b)

#define CG_MULT(irType, a, b) \
   CG_BINOP_TYPED("BVMULT", irType, a, b)

#define CG_UMOD(irType, a, b) \
   CG_BINOP_TYPED("BVMOD", irType, a, b)

#define CG_UDIV(irType, a, b) \
   CG_BINOP_TYPED("BVDIV", irType, a, b)

#define CG_SMOD(irType, a, b) \
   CG_BINOP_TYPED("SBVMOD", irType, a, b)

#define CG_SDIV(irType, a, b) \
   CG_BINOP_TYPED("SBVDIV", irType, a, b)



#define CG_NOT(a) \
   CG_UNOP("NOT", a);

#define CG_INV(a) \
   CG_UNOP("~", a);

#define CG_EQUAL(a, b) \
   a; CgenOut(" = "); b;

#define CG_ITE(a, b, c) \
   CgenOut("(IF "); a; CgenOut(" THEN "); b; CgenOut(" ELSE "); c; CgenOut(" ENDIF)");

#define CG_SHIFT(opStr, a, b) \
   ({if (b > 0) { \
      CG_BINOP_INFIX(opStr, a, CG_DEC(b)); \
   } else if (b == 0) { \
      /* STP doesn't like shifts by 0. */ \
      a; \
   } else { \
      ASSERT(0); \
   }});

#define CG_SHIFT_PREFIX(opStr, a, b) \
   ({ if (b > 0) { \
      CG_BINOP(opStr, a, CG_DEC(b)); \
   } else if (b == 0) { \
      /* STP doesn't like shifts by 0. */ \
      a; \
   } else { \
      ASSERT(0); \
   } });

#define CG_SHL(irType, a, b) \
   CG_CAST(irType, CG_SHIFT("<<", a, b));

/* Right-shifting doesn't alter size. */
#define CG_SHR(irType /* for uniformity */, a, b) \
   CG_SHIFT(">>", a, b);

/* Careful: STP's sign-extended right shift alters target size. */
#define CG_SAR(irType, a, b) \
   CG_EXTRACT(CG_SHIFT_PREFIX("BVSX", a, (T2B(irType)+b)), \
         (T2B(irType)+b-1), (b));

#define CG_ASSERT(f) \
   CgenOut("ASSERT("); f; CgenOut(");\n"); cgPrint_Commit();

#define CG_ASSIGN(l, r) \
   CG_ASSERT({l; CgenOut(" = "); r;});

#define CG_EQUIV(l, r) \
   CG_ASSERT({l; CgenOut(" <=> "); r;});



/* Declaration helpers. */
#define CG_NEW_LOCAL_SCOPE() \
   cg_StartNewLocalScope()

#define CG_NEW_ARRAY(sizeBits, irType, nameStr) \
   CgenOut("%s : ARRAY BITVECTOR(%d) OF BITVECTOR(%d);\n", nameStr, sizeBits, IRTYPE2BITS(irType)); cgPrint_Commit();

#define CG_NEW_BOOL(l) \
   l; CgenOut(" : BOOLEAN;\n"); cgPrint_Commit();

#define CG_NEW_VAR(irType, l) \
   l; CgenOut(" : BITVECTOR(%d);\n", IRTYPE2BITS(irType)); cgPrint_Commit();

#define CG_NEW_VAR_INIT(irType, l, r) \
   CG_NEW_VAR(irType, l); \
   CG_ASSIGN(l, r);


#define CG_NEW_TMP_INIT(irType, tmpName, r) \
   cg_DeclareTmp(tmpName, irType); \
   CG_ASSIGN(CG_TMP(tmpName), r);

/* Variables. */

/* Prints value in decimal. */
#define CG_DEC(v) \
   CgenOut("%llu", (ULong)v);

/* Prints in hex. */
#define CG_CONST_BITS(v, b) \
   ({CgenOut("0hex%.16llx[%d:0]", (ULong)v, b);})

#define CG_CONST(irType, v) \
   CG_CONST_BITS(v, IRTYPE2BITS(irType)-1);

#define CG_CV(cv) \
   ({cg_PrintCondVar(cv);})

#define CG_BV(bv) \
   ({cg_PrintByteVar(bv);})

#define CG_TMP(t) \
   cg_PrintTmpVarNow(t)

#define CG_ELEM(avStr, i) \
   CgenOut("%s[", avStr); i; CgenOut("]");


#define CG_ARG(ty, argp) \
   cg_PrintArg(ty, argp);

#define CG_ARG_DEF(argp) \
   cg_PrintArg((argp)->ty, argp);

/* Reference a variable defined within the most recent local 
 * scope. */
#define CG_LSCOPE(s) \
   cg_PrintLocalVarNow(s, 0)

#define CG_LSCOPEI(i) \
   cg_PrintLocalVarNow("", i)

#define CG_LSCOPE_NAMED(s, i) \
   cg_PrintLocalVarNow(s, i)

/* Misc. */
#define CG_COMMENT(s, ...) \
   if (wantsComments) { \
      CgenOut("%% "); \
      CgenOut(s, ##__VA_ARGS__); \
      cgPrint_Commit(); \
   }
