package z80core;

class TaintedValue {
	public int value;
	public int tainted;
	
	TaintedValue( TaintedValue cp ) {
		value = cp.value;
		tainted = cp.tainted;
	}
	
	TaintedValue( int v ) {
		value = v;
		tainted = 0;
	}
	
	TaintedValue( int v, int t ) {
		value = v;
		tainted = t;
	}
};