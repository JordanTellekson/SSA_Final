namespace SSA_Final.Interfaces
{
    public interface IDnsResolver
    {
        Task<bool> HasRecordsAsync(string domain);
    }
}
