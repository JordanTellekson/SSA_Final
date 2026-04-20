namespace SSA_Final.Models
{
    /// <summary>
    /// Score object for an individual risk signal and its explanation.
    /// </summary>
    public class DomainRiskSignalScore
    {
        /// <summary>
        /// Creates a risk-signal score payload.
        /// </summary>
        /// <param name="signal">Signal name.</param>
        /// <param name="score">Numeric score contribution.</param>
        /// <param name="triggered">Whether the signal triggered.</param>
        /// <param name="detail">Human-readable score explanation.</param>
        public DomainRiskSignalScore(string signal, int score, bool triggered, string detail)
        {
            Signal = signal;
            Score = score;
            Triggered = triggered;
            Detail = detail;
        }

        /// <summary>
        /// Signal category label.
        /// </summary>
        public string Signal { get; }

        /// <summary>
        /// Numeric score contributed by this signal.
        /// </summary>
        public int Score { get; }

        /// <summary>
        /// Indicates whether this signal was triggered.
        /// </summary>
        public bool Triggered { get; }

        /// <summary>
        /// Detailed explanation of how the score was determined.
        /// </summary>
        public string Detail { get; }
    }
}
