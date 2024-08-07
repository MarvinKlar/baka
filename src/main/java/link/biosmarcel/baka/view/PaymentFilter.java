package link.biosmarcel.baka.view;

import link.biosmarcel.baka.data.Payment;
import link.biosmarcel.baka.filter.Filter;
import link.biosmarcel.baka.filter.Operator;

import java.time.LocalDate;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;

public class PaymentFilter extends Filter<Payment> {
    private static final DateTimeFormatter DATE_FORMAT = new DateTimeFormatterBuilder().appendPattern("d.M.[uuuu][uu]").toFormatter();

    {
        register("name", Operator.EQ, (payment, value) -> payment.name.equalsIgnoreCase(value), String::toLowerCase);
        register("name", Operator.NOT_EQ, (payment, value) -> !payment.name.equalsIgnoreCase(value), String::toLowerCase);
        register("name", Operator.HAS, (payment, value) -> payment.name.toLowerCase().contains(value), String::toLowerCase);

        register("reference", Operator.EQ, (payment, value) -> payment.reference.equalsIgnoreCase(value), String::toLowerCase);
        register("reference", Operator.NOT_EQ, (payment, value) -> !payment.reference.equalsIgnoreCase(value), String::toLowerCase);
        register("reference", Operator.HAS, (payment, value) -> payment.reference.toLowerCase().contains(value), String::toLowerCase);

        register("participant", Operator.EQ, (payment, value) -> payment.participant != null && payment.participant.equalsIgnoreCase(value), String::toLowerCase);
        register("participant", Operator.NOT_EQ, (payment, value) -> payment.participant == null || payment.participant.equalsIgnoreCase(value), String::toLowerCase);
        register("participant", Operator.HAS, (payment, value) -> payment.participant != null && payment.participant.toLowerCase().contains(value), String::toLowerCase);

        register("effective_date", Operator.LT, (payment, value) -> payment.effectiveDate.isBefore(value), value -> LocalDate.parse(value, DATE_FORMAT).atStartOfDay());
        register("effective_date", Operator.GT, (payment, value) -> payment.effectiveDate.isAfter(value), value -> LocalDate.parse(value, DATE_FORMAT).atTime(LocalTime.MAX));
        register("effective_date", Operator.LT_EQ, (payment, value) -> payment.effectiveDate.getLong(ChronoField.EPOCH_DAY) <= value, value -> LocalDate.parse(value, DATE_FORMAT).toEpochDay());
        register("effective_date", Operator.GT_EQ, (payment, value) -> payment.effectiveDate.getLong(ChronoField.EPOCH_DAY) >= value, value -> LocalDate.parse(value, DATE_FORMAT).toEpochDay());
        register("effective_date", Operator.EQ, (payment, value) -> payment.effectiveDate.getLong(ChronoField.EPOCH_DAY) == value, value -> LocalDate.parse(value, DATE_FORMAT).toEpochDay());

        register("booking_date", Operator.LT, (payment, value) -> payment.bookingDate.isBefore(value), value -> LocalDate.parse(value, DATE_FORMAT).atStartOfDay());
        register("booking_date", Operator.GT, (payment, value) -> payment.bookingDate.isAfter(value), value -> LocalDate.parse(value, DATE_FORMAT).atTime(LocalTime.MAX));
        register("booking_date", Operator.LT_EQ, (payment, value) -> payment.bookingDate.getLong(ChronoField.EPOCH_DAY) <= value, value -> LocalDate.parse(value, DATE_FORMAT).toEpochDay());
        register("booking_date", Operator.GT_EQ, (payment, value) -> payment.bookingDate.getLong(ChronoField.EPOCH_DAY) >= value, value -> LocalDate.parse(value, DATE_FORMAT).toEpochDay());
        register("booking_date", Operator.EQ, (payment, value) -> payment.bookingDate.getLong(ChronoField.EPOCH_DAY) == value, value -> LocalDate.parse(value, DATE_FORMAT).toEpochDay());
    }
}
