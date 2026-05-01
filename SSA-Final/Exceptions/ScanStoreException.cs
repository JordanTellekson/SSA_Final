namespace SSA_Final.Exceptions
{
    /// <summary>
    /// Thrown when a persistence operation in <see cref="SSA_Final.Services.SqlScanStoreService"/>
    /// fails. Wraps the underlying database exception so callers are not coupled to EF Core or
    /// SQL Server implementation details.
    /// </summary>
    public class ScanStoreException : Exception
    {
        public ScanStoreException(string message, Exception innerException)
            : base(message, innerException) { }
    }
}
