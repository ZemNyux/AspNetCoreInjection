namespace WebApplication1.Models
{
    public class Order
    {
        public int Id { get; set; }
        public string UserId { get; set; } = null!;

        public string? ProductName { get; set; }
        public decimal Price { get; set; }
        public string? Address { get; set; }
    }
}