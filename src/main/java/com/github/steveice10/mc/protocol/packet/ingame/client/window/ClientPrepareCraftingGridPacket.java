package com.github.steveice10.mc.protocol.packet.ingame.client.window;

import com.github.steveice10.packetlib.io.NetInput;
import com.github.steveice10.packetlib.io.NetOutput;
import com.github.steveice10.packetlib.packet.Packet;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;

import java.io.IOException;

@Data
@Setter(AccessLevel.NONE)
@NoArgsConstructor()
@AllArgsConstructor
public class ClientPrepareCraftingGridPacket implements Packet {
    private int windowId;
    private @NonNull String recipeId;
    private boolean makeAll;

    @Override
    public void read(NetInput in) throws IOException {
        this.windowId = in.readByte();
        this.recipeId = in.readString();
        this.makeAll = in.readBoolean();
    }

    @Override
    public void write(NetOutput out) throws IOException {
        out.writeByte(this.windowId);
        out.writeString(this.recipeId);
        out.writeBoolean(this.makeAll);
    }

    @Override
    public boolean isPriority() {
        return false;
    }
}
