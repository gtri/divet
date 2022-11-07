package m68k;

public class TaintedValue {
	public int value;
	public int tainted;
	
	public TaintedValue(int value, int tainted) {
		this.value = value;
		this.tainted = tainted;
	}
	
	public TaintedValue(TaintedValue value) {
		this.value = value.value;
		this.tainted = value.tainted;
	}
	
	public boolean equals(TaintedValue value) {
		if( this.value == value.value && this.tainted == value.tainted )
			return true;
		else
			return false;
	}
}