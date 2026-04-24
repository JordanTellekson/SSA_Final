// Immutable model representing one risk signal, its score contribution, and detail.

namespace SSA_Final.Models
{
    // Individual risk-signal score (one of the risk checks) with context details.
    public class DomainRiskSignalScore
    {
        public DomainRiskSignalScore(string signal, int score, bool triggered, string detail)
        {
            Signal = signal;
            Score = score;
            Triggered = triggered;
            Detail = detail;
        }

        public string Signal { get; }

        public int Score { get; }

        public bool Triggered { get; }

        public string Detail { get; }
    }
}


